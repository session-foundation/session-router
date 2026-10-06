#include "path.hpp"

#include "crypto/crypto.hpp"
#include "link/endpoint.hpp"
#include "messages/common.hpp"
#include "nodedb.hpp"
#include "path_handler.hpp"
#include "profiling.hpp"
#include "router/router.hpp"
#include "util/bspan.hpp"
#include "util/logging/buffer.hpp"

#include <nlohmann/json.hpp>
#include <oxenc/bt_producer.h>

#include <chrono>
#include <ranges>

namespace srouter::path
{
    static auto logcat = log::Cat("path");

    size_t Path::next_path_log_id = 0;

    Path::Path(Router& rtr, std::span<const RelayContact> hop_rcs, sys_ms expiry_ts)
        : _router{rtr}, _expiry{expiry_ts}, path_log_id{++next_path_log_id}
    {
        hops.resize(hop_rcs.size());

        for (size_t i = 0; i < hop_rcs.size(); ++i)
        {
            const bool last = i + 1 == hop_rcs.size();
            auto& hop = hops[i];
            hop.router_id = hop_rcs[i].router_id();
            // First hop RXID is unique, the rest are the previous hop TXID
            hop.rxid = i == 0 ? HopID::make_random() : hops[i - 1].txid;
            // Pivot hop TXID is not useful, and so is simply set equal to the pivot RXID.
            hop.txid = last ? hop.rxid : HopID::make_random();
            // Last hop upstream is it's own RID, the rest are the next hop RID
            hop.upstream = last ? hop.router_id : hop_rcs[i + 1].router_id();
            // First hop downstream is client's RID, the rest are the previous hop RID
            hop.downstream = i == 0 ? _router.id() : hops[i - 1].router_id;

            // hop.shared_secret and hop.xor_nonce are not set yet: they get set via a call to
            // PathHandler::path_build_onion when we make the actual build path message (because
            // they also require generating and sending an ephemeral pubkey and dh nonce in the path
            // build message, which aren't required again once sent in that message).
        }

        hops.back().terminal_hop = true;

        log::trace(logcat, "Path populated with hops: {}", hop_string());

        log::debug(logcat, "Path successfully constructed: {}", *this);
    }

    ClientIntro Path::make_intro() const
    {
        ClientIntro intro;
        intro.relay = hops.back().router_id;
        intro.hop = hops.back().txid;
        intro.expiry = std::chrono::sys_seconds{std::chrono::floor<std::chrono::seconds>(_expiry)};
        return intro;
    }

    std::string Path::ping_stats_printer::to_string() const
    {
        if (p.ping_responses == 0)
            return "0.0%";

        double mean = (double)p.ping_cumulative.count() / p.ping_responses;
        double success_pct = p.ping_responses / (double)(p.ping_responses + p.ping_timeouts) * 100.0;
        if (p.ping_responses == 1)
            return "{:.1f}%, {:.0f}ms avg"_format(success_pct, mean);
        double jitter = p.ping_responses < 2 ? 0.0 : (double)p.ping_abs_diffs.count() / (p.ping_responses - 1);
        return "{:.1f}%, {:.0f}ms avg, {:.1f}ms jitter"_format(success_pct, mean, jitter);
    }

    void Path::do_ping(steady_ms start_time)
    {
        if (!is_active() || start_time < next_ping)
            return;

        // Subtract a few milliseconds so that jitter in the tick processing time doesn't affect the
        // ping interval:
        next_ping = start_time + _router.config().paths.ping_interval - 20ms;

        log::trace(logcat, "Pinging path TXID={}", edge().txid);
        send_path_control_message(
            "path_ping", {}, [this, wself = weak_from_this(), start_time](path_control_response resp) {
                auto sself = wself.lock();
                if (!sself)
                    return;
                auto now = steady_now_ms();
                auto time_taken = now - start_time;
                if (resp.ok())
                {
                    if (++ping_responses > 1)
                        ping_abs_diffs += time_taken >= ping_last ? time_taken - ping_last : ping_last - time_taken;
                    ping_last = time_taken;
                    ping_recent_timeouts = 0;
                    ping_cumulative += time_taken;

                    if (resp.body == messages::OK_RESPONSE)
                        log::debug(
                            logcat,
                            "Ping response for path {} (txid={}) response received in {} ({})",
                            *this,
                            edge().txid,
                            time_taken,
                            printable_ping_stats());
                    else
                        log::warning(
                            logcat,
                            "Path {} ping was successful (in {}) but had unexpected response body: {}",
                            *this,
                            time_taken,
                            buffer_printer(resp.body));
                }
                else
                {
                    bool expire = true;
                    if (resp.timed_out)
                    {
                        ping_timeouts++;
                        log::debug(
                            logcat,
                            "Ping response for path {} (txid={}) timed out after {} ({})",
                            *this,
                            edge().txid,
                            time_taken,
                            printable_ping_stats());
                        expire = ++ping_recent_timeouts > _router.config().paths.max_missed_pings;
                        if (expire)
                            log::warning(
                                logcat,
                                "Path {} (txid={}) had too many ping timeouts ({}); expiring path.",
                                *this,
                                edge().txid,
                                ping_recent_timeouts);
                    }
                    else
                        log::warning(
                            logcat,
                            "{} path_ping returned a path error (in {}): {}",
                            *this,
                            time_taken,
                            buffer_printer(resp.body));

                    if (expire)
                        _expiry = {};
                }
            });
    }

    bool Path::operator==(const Path& other) const
    {
        return std::ranges::equal(
            hops, other.hops, [](const TransitHop& a, const TransitHop& b) { return a.same_transit(b); });
    }

    void Path::fetch_relay_contacts(std::span<const std::byte> body, std::function<void(path_control_response)> func)
    {
        send_path_control_message("fetch_rcs", body, std::move(func));
    }

    void Path::find_client_contact(
        const PubKey& blinded_pk, int lookup_index, std::function<void(path_control_response)> func)
    {
        oxenc::bt_dict_producer btdp;
        btdp.append("k"sv, blinded_pk.span());
        btdp.append("n"sv, lookup_index);
        send_path_control_message("find_cc", btdp.span<std::byte>(), std::move(func));
    }

    void Path::publish_client_contact(
        std::string_view encrypted_cc, int location, std::function<void(path_control_response)> func)
    {
        oxenc::bt_dict_producer btdp;
        btdp.append("e"sv, encrypted_cc);
        btdp.append("n"sv, location);
        send_path_control_message("publish_cc", btdp.span<std::byte>(), std::move(func));
    }

    void Path::resolve_sns(std::span<const std::byte, 32> name_hash, std::function<void(path_control_response)> func)
    {
        oxenc::bt_dict_producer btdp;
        btdp.append("s"sv, name_hash);
        send_path_control_message("resolve_sns", btdp.span<std::byte>(), std::move(func));
    }

    void Path::encrypt_path_message(std::vector<std::byte>& data, SymmNonce&& nonce, MessageType type, bool with_mac)
    {
        auto& hopid = edge().rxid;
        auto inner_size = data.size() + (with_mac ? crypto::TAG_SIZE : 0);
        data.resize(inner_size + ENCRYPT_PATH_MESSAGE_OVERHEAD);

        static_assert(sizeof(SymmNonce) == SymmNonce::SIZE);
        static_assert(sizeof(HopID) == HopID::SIZE);

        auto [inner_payload, bnonce, bhop, msgtype] = split_span_tail<SymmNonce::SIZE, HopID::SIZE, 1>(data);
        assert(inner_payload.size() == inner_size);

        bool first{true};
        for (const auto& hop : std::ranges::reverse_view(hops))
        {
            if (first && with_mac)
            {
                first = false;
                crypto::xchacha20_poly1305_encrypt_inplace(inner_payload, hop.shared_secret, nonce);
            }
            else
                crypto::xchacha20(inner_payload, hop.shared_secret, nonce);

            nonce ^= hop.xor_nonce;
        }

        nonce.copy_to(bnonce);
        hopid.copy_to(bhop);
        msgtype[0] = static_cast<std::byte>(type);
    }

    std::string Path::decrypt_path_message(std::string_view payload)
    {
        if (payload.size() <= ENCRYPT_PATH_MESSAGE_OVERHEAD_MAC)
        {
            log::warning(logcat, "received too-short response to path control message.");
            return {};
        }
        std::string body{payload};
        std::span<std::byte> body_span{reinterpret_cast<std::byte*>(body.data()), body.size()};
        auto [inner_payload, bnonce, bhop, msgtype] = split_span_tail<SymmNonce::SIZE, HopID::SIZE, 1>(body_span);
        SymmNonce nonce;
        nonce.assign(bnonce);
        for (size_t i = 0; i != hops.size() - 1; i++)
        {
            nonce ^= hops[i].xor_nonce;
            crypto::xchacha20(inner_payload, hops[i].shared_secret, nonce);
        }
        const auto& last_hop = hops.back();
        nonce ^= last_hop.xor_nonce;
        if (auto decrypted = crypto::xchacha20_poly1305_decrypt_inplace(inner_payload, last_hop.shared_secret, nonce))
            return {reinterpret_cast<const char*>(decrypted->data()), decrypted->size()};

        log::warning(logcat, "path control message response decryption failed");
        return {};
    }

    void Path::send_path_data_message(std::vector<std::byte>&& data, SymmNonce&& nonce)
    {
        encrypt_path_message(data, std::move(nonce), MessageType::Data, false /* mac on session payload */);
        _router.link_endpoint().send_datagram(edge().router_id, std::move(data));
    }

    void Path::send_path_control_message(
        std::string_view method, std::span<const std::byte> body, std::function<void(path_control_response)> func)
    {
        auto decryptor = [wself = weak_from_this(), func = std::move(func)](quic::message m) {
            path_control_response resp;

            auto self = wself.lock();
            if (!self)
            {
                log::info(logcat, "Path control response received, but path is gone.");
                resp.timed_out = true;
                func(std::move(resp));
                return;
            }

            resp.timed_out = m.timed_out;
            resp.error = !m;
            if (m.timed_out || m.is_error())
                resp.body = m.body();
            else
                resp.body = self->decrypt_path_message(m.body());
            func(std::move(resp));
        };

        oxenc::bt_dict_producer btdp;
        btdp.append("e"sv, method);
        btdp.append("p"sv, body);
        auto inner_payload = btdp.view();
        std::vector<std::byte> payload;
        payload.reserve(inner_payload.size() + ENCRYPT_PATH_MESSAGE_OVERHEAD_MAC);
        payload.resize(inner_payload.size());
        std::memcpy(payload.data(), inner_payload.data(), inner_payload.size());
        encrypt_path_message(payload, SymmNonce::make_random(), MessageType::Control, true /* include mac */);
        _router.link_endpoint().send_command(
            edge().router_id, "path_control", std::move(payload), std::move(decryptor));
    }

    void Path::send_session_control_message(std::vector<std::byte>&& body, SymmNonce&& nonce, MessageType type)
    {
        encrypt_path_message(body, std::move(nonce), type, false /* mac on session payload */);
        _router.link_endpoint().send_command(edge().router_id, "session_control", std::move(body), nullptr);
    }

    std::string Path::to_string() const { return "Path{{{}}}[{}]"_format(path_log_id, hop_string()); }

    std::string path_hop_stringifier::to_string() const
    {
        return fmt::to_string(
            fmt::join(hops | std::views::transform([](auto& h) { return h.router_id.short_string(); }), "⟷"));
    }
    path_hop_stringifier Path::hop_string() const { return {hops}; }

    Path::Info Path::get_info() const
    {
        Info ret{};
        ret.expiry = _expiry;
        if (ping_responses)
            ret.ping_mean = std::chrono::round<std::chrono::milliseconds>(
                std::chrono::nanoseconds{ping_cumulative} / ping_responses);
        if (ping_responses > 1)
            ret.ping_jitter = std::chrono::round<std::chrono::microseconds>(
                std::chrono::nanoseconds{ping_abs_diffs} / (ping_responses - 1));
        ret.ping_responses = ping_responses;
        ret.ping_timeouts = ping_timeouts;
        ret.ping_recent_timeouts = ping_recent_timeouts;
        for (const auto& hop : hops)
        {
            auto* rc = _router.node_db().get_rc(hop.router_id);
            if (rc)
                ret.relays.emplace_back(hop.router_id, rc->addr().to_ipv4());
            else
            {
                log::warning(logcat, "Couldn't find RC of a router on our path?!");
                ret.relays.emplace_back();
            }
        }
        return ret;
    }

    void Path::set_established()
    {
        if (_is_established)
            return;

        log::trace(logcat, "Path marked as successfully established!");
        _is_established = true;
    }

    std::string Path::name() const { return "[ TX={} | RX={} ]"_format(edge().txid, edge().rxid); }

}  // namespace srouter::path
