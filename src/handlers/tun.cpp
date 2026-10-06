#include "tun.hpp"

#include <oxen/log.hpp>
#include <oxenc/base32z.h>
#include <oxenc/endian.h>

#include <chrono>
#include <span>
#include <variant>
#ifndef _WIN32
#include <sys/socket.h>
#endif

#include "auth/auth.hpp"
#include "constants/platform.hpp"
#include "contact/sns.hpp"
#include "dns/encode.hpp"
#include "nodedb.hpp"
#include "router/route_poker.hpp"
#include "router/router.hpp"
#include "util/logging/buffer.hpp"
#include "util/str.hpp"

#include <nlohmann/json.hpp>

namespace srouter::handlers
{
    static auto logcat = log::Cat("tun");

    TunEndpoint::TunEndpoint(Router& r) : _router{r}
    {
        _packet_router =
            std::make_shared<vpn::PacketRouter>([this](IPPacket pkt) { handle_outbound_packet(std::move(pkt)); });

        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        auto& net_conf = _router.config().network;

        _exit_policy = net_conf.traffic_policy;

        _if_name = net_conf._if_name.value_or("");

        // These should have been assigned by Router before this; they might, however, still be
        // quad-0 or :: to indicate autoselection of an unused range.
        assert(net_conf._local_ip_net);
        assert(net_conf._local_ipv6_net);

        vpn::InterfaceInfo info;
        info.ifname = _if_name;
        info.addrs.emplace_back(*net_conf._local_ip_net);
        info.addrs.emplace_back(*net_conf._local_ipv6_net);

        log::debug(logcat, "{} setting up network...", name());

        _net_if = router().vpn_platform()->create_interface(std::move(info), &_router);
        _if_name = _net_if->interface_info().ifname;

        log::info(logcat, "{} got network interface:{}", name(), _if_name);

        // Load the addresses out of the interface, *not* the config, because the interface
        // construction will have done auto-selection for any 0 addresses:
        for (auto& addr : _net_if->interface_info().addrs)
        {
            if (auto* n4 = std::get_if<ipv4_net>(&addr))
                _local_net = *n4;
            else
                _local_ipv6_net = std::get<ipv6_net>(addr);
        }

#if 0
        if (net_conf.addr_map_persist_file)
        {
            _persisting_addr_file = net_conf.addr_map_persist_file;
            persist_addrs = true;
        }
#endif

        NetworkAddress me{_router.id(), !_router.is_service_node};
        _local_ipv4_mapping.insert(_local_net.ip, me);
        _local_ipv6_mapping.insert(_local_ipv6_net.ip, std::move(me));

        auto add_mappings = [](const auto& local_net, auto& mapping, const auto& reserved) {
            for (auto& [remote, local] : reserved)
            {
                if (!local_net.contains(local))
                {
                    log::error(
                        logcat,
                        "Unable to apply {} <-> {} IP mapping: that IP is not inside the local network range {}",
                        remote,
                        local,
                        local_net);
                    continue;
                }
                if (mapping.contains(remote))
                {
                    log::error(
                        logcat, "Unable to apply {} <-> {} IP mapping: that remote is already assigned", remote, local);
                    continue;
                }
                if (mapping.contains(local))
                {
                    log::error(
                        logcat, "Unable to apply {} <-> {} IP mapping: that IP is already assigned", local, remote);
                    continue;
                }
                mapping.insert(local, remote);
            }
        };
        add_mappings(_local_net, _local_ipv4_mapping, net_conf._reserved_local_ipv4);
        add_mappings(_local_ipv6_net, _local_ipv6_mapping, net_conf._reserved_local_ipv6);

        log::debug(logcat, "Tun constructing IPRange iterator on local networks: {}, {}", _local_net, _local_ipv6_net);
        _local_range_iterator = IPRangeIterator{_local_net};
        _local_ipv6_range_iterator = IPv6RangeIterator{_local_ipv6_net};
    }

    static const auto random_snode = "random.{}"_format(RELAY_TLD);

    std::string TunEndpoint::get_if_name() const { return _if_name; }

    const ipv4& TunEndpoint::get_ipv4() const { return _local_net.ip; }
    const ipv6& TunEndpoint::get_ipv6() const { return _local_ipv6_net.ip; }

    const ipv4_net& TunEndpoint::get_ipv4_network() const { return _local_net; }
    const ipv6_net& TunEndpoint::get_ipv6_network() const { return _local_ipv6_net; }

    bool TunEndpoint::is_service_node() const { return _router.is_service_node; }

    bool TunEndpoint::is_exit_node() const { return _router.is_exit_node(); }

    void TunEndpoint::stop()
    {
        // stop vpn tunnel
        if (_net_if)
            _net_if->Stop();

#if 0
        // save address map if applicable
        if (_persisting_addr_file and not platform::is_android)
        {
            const auto& file = *_persisting_addr_file;
            log::debug(logcat, "{} saving address map to {}", name(), file);
            // if (auto maybe = util::OpenFileStream<std::filesystem::ofstream>(file, std::ios_base::binary))
            // {
            //   std::map<std::string, std::string> addrmap;
            //   for (const auto& [ip, addr] : m_IPToAddr)
            //   {
            //     if (not m_SNodes.at(addr))
            //     {
            //       const service::Address a{addr.as_array()};
            //       if (HasInboundConvo(a))
            //         addrmap[ip.to_string()] = a.to_string();
            //     }
            //   }
            //   const auto data = oxenc::bt_serialize(addrmap);
            //   maybe->write(data.data(), data.size());
            // }
        }
#endif
    }

    template <typename RangeIterator>
    static std::optional<typename RangeIterator::ip_t> get_next_local_ipvX(
        RangeIterator& rit,
        const typename RangeIterator::ip_net_t& local_net,
        address_map<typename RangeIterator::ip_t>& local_mapping)
    {
        // if our IP range is exhausted, we loop back around to see if any have been unmapped from terminated
        // sessions; we only want to reset the iterator and loop back through once though
        bool has_reset = false;

        do
        {
            // this will be std::nullopt if IP range is exhausted OR the IP incrementing overflowed (basically
            // equal)
            if (auto maybe_next_ip = rit.next_ip())
            {
                if (not local_mapping.contains(*maybe_next_ip))
                    return maybe_next_ip;
                // local IP is already assigned; try again
                continue;
            }

            if (has_reset)
                break;

            log::debug(logcat, "Resetting IP range iterator for range: {}...", local_net);
            rit.reset();
            has_reset = true;
        } while (true);

        return std::nullopt;
    }

    std::optional<ipv4> TunEndpoint::get_next_local_ipv4()
    {
        return get_next_local_ipvX(_local_range_iterator, _local_net, _local_ipv4_mapping);
    }

    std::optional<ipv6> TunEndpoint::get_next_local_ipv6(const NetworkAddress& a)
    {
        // If we have at least a /64 (which we usually do) then first try using the prefix of `a` as
        // a network address itself; if this is available, we use it, so that typically the same
        // pubkey gets the same local address.  If that fails, however, because of a prefix
        // collision then we fall back to sequential allocation from the beginning of the range.
        uint8_t addr_bits = 128 - _local_ipv6_net.mask;

        const auto& rid = a.pubkey;
        size_t addr_bytes = addr_bits / 8;
        auto to_try = std::make_optional<ipv6>(_local_ipv6_net.ip);
        if (addr_bytes > 8)
        {
            uint64_t hi_bits = 0;
            std::memcpy(reinterpret_cast<char*>(&hi_bits) + 8 - (addr_bytes - 8), rid.data(), addr_bytes - 8);
            oxenc::big_to_host_inplace(hi_bits);
            to_try->hi |= hi_bits;
        }
        if (addr_bytes >= 8)
            to_try->lo = oxenc::load_big_to_host<uint64_t>(rid.data() + addr_bytes - 8);
        else
        {
            uint64_t lo_bits = 0;
            std::memcpy(reinterpret_cast<char*>(&lo_bits) + 8 - addr_bytes, rid.data(), addr_bytes);
            oxenc::big_to_host_inplace(lo_bits);
            to_try->lo |= lo_bits;
        }

        assert(_local_ipv6_net.contains(*to_try));
        // A pubkey with a zero prefix maps onto the base address of the range, which is the
        // subnet-router anycast address and so must never be handed out as a host address.
        if (!_local_ipv6_mapping.contains(*to_try) && *to_try != _local_ipv6_net.ip
            && *to_try != _local_ipv6_net.ip.to_base(_local_ipv6_net.mask))
        {
            log::debug(logcat, "Assigning pubkey-based local IPv6 {} for remote {}", *to_try, a);
            return to_try;
        }
        log::debug(
            logcat,
            "Pubkey-based local IPv6 {} for remote {} is unavailable; falling back to sequential IPv6 allocation",
            *to_try,
            a);

        return get_next_local_ipvX(_local_ipv6_range_iterator, _local_ipv6_net, _local_ipv6_mapping);
    }

    ipv6 TunEndpoint::map6(const NetworkAddress& remote)
    {
        ipv6 ret;
        if (auto maybe_ipv6 = _local_ipv6_mapping[remote])
        {
            ret = std::move(*maybe_ipv6);
            log::debug(logcat, "Local IP for session to remote ({}) already assigned ({})", remote, ret);
        }
        else if (auto maybe_next = get_next_local_ipv6(remote))
        {
            ret = std::move(*maybe_next);
            log::debug(logcat, "Local IP for session to remote ({}) assigned: {}", remote, ret);
            _local_ipv6_mapping.insert(ret, remote);
        }
        else
        {
            // This should not happen unless you have forced a stupidly small IPv6 range
            log::critical(logcat, "TUN device could not find a local private IPv6 for remote: {}", remote);
            throw std::runtime_error{
                "TUN device could not allocate an IPv6; perhaps the IPv6 netmask is much too restrictive?"};
        }

        return ret;
    }

    std::optional<ipv4> TunEndpoint::map4(const NetworkAddress& remote)
    {
        std::optional<ipv4> ret;

        // first: check if we already have a mapping for this remote
        ret = _local_ipv4_mapping[remote];
        if (ret)
            log::debug(logcat, "Local IP for session to remote ({}) already assigned ({})", remote, *ret);
        else
        {
            ret = get_next_local_ipv4();
            if (ret)
            {
                _local_ipv4_mapping.insert(*ret, remote);
                log::debug(logcat, "Local IP for session to remote ({}) assigned: {}", remote, *ret);
            }
            else
                log::error(
                    logcat,
                    "TUN device could not find a local private IPv4 for remote: {}; perhaps you need a "
                    "larger IPv4 network (i.e. smaller netmask)?",
                    remote);
        }

        return ret;
    }

    void TunEndpoint::expire(const NetworkAddress& remote)
    {
        // If already in the expired list, extract it before we re-add to the end
        if (auto it = _exp_it.find(remote); it != _exp_it.end())
        {
            _expired.erase(it->second);
            _exp_it.erase(it);
        }
        _exp_it[remote] = _expired.emplace(_expired.end(), remote);

        prune_expired();
    }

    void TunEndpoint::prune_expired()
    {
        size_t keep = _router.config().network.expired_address_cache;
        while (_expired.size() > keep)
        {
            auto& remote = _expired.front();
            _local_ipv4_mapping.erase(remote);
            _local_ipv6_mapping.erase(remote);
            _exp_it.erase(_expired.front());
            _expired.pop_front();
        }
    }

    // handles an outbound packet going OUT from user -> network
    void TunEndpoint::handle_outbound_packet(IPPacket pkt)
    {
        const bool is_v4 = pkt.is_ipv4();

        if (!is_v4 && !pkt.is_ipv6())
        {
            log::debug(logcat, "Dropping non-IP packet");
            log::trace(logcat, "Packet: {}", buffer_printer{pkt.span()});
            return;
        }

        log::trace(logcat, "outbound packet: {}: {}", pkt.info_line(), buffer_printer{pkt.span()});

        ipv4 src4, dest4;
        ipv6 src6, dest6;

        if (is_v4)
        {
            src4 = *pkt.source_ipv4();
            dest4 = *pkt.dest_ipv4();
            log::trace(logcat, "src:{}, dest:{}", src4, dest4);
        }
        else
        {
            src6 = *pkt.source_ipv6();
            dest6 = *pkt.dest_ipv6();
            log::trace(logcat, "src:{}, dest:{}", src6, dest6);
        }

        if constexpr (srouter::platform::is_apple)
        {
            if (is_v4)
            {
                if (dest4 == _local_net.ip)
                {
                    rewrite_and_send_packet(std::move(pkt), std::move(src4), std::move(dest4));
                    return;
                }
            }
            else if (dest6 == _local_ipv6_net.ip)
            {
                rewrite_and_send_packet(std::move(pkt), std::move(src6), std::move(dest6));
                return;
            }
        }

        // we pass `dest` because that is our local private IP on the outgoing IPPacket
        if (auto remote = is_v4 ? _local_ipv4_mapping[dest4] : _local_ipv6_mapping[dest6])
        {
            pkt.clear_addresses();

            if (auto session = _router.session_endpoint().get_session(*remote))
            {
                log::trace(
                    logcat,
                    "Dispatching outbound {}B packet for session (remote: {}): {}",
                    pkt.size(),
                    *remote,
                    pkt.info_line());
                session->send_session_data_message(pkt.span(), pkt.protocol());
            }
            else
            {
                log::debug(logcat, "No session for remote: {} for outbound packet, attempting to create one!", *remote);

                std::shared_ptr<session::Session> s;
                try
                {
                    s = _router.session_endpoint().initiate_remote_session(*remote, nullptr);
                }
                catch (const std::exception& e)
                {
                    log::debug(logcat, "Failed to auto-initiate session to remote {}: {}", *remote, e.what());
                }

                if (s)
                    s->send_session_data_message(pkt.span(), pkt.protocol());
            }
        }
        else
        {
            log::trace(logcat, "Could not find remote for route {}", pkt.info_line());

            // make ICMP unreachable
            if (auto icmp = pkt.make_icmp_unreachable())
                send_packet_to_net_if(std::move(*icmp));
        }
    }

    std::optional<ipv4> TunEndpoint::obtain_src_for_ipv4_remote(const NetworkAddress& remote)
    {
        if (auto maybe_src = _local_ipv4_mapping[remote])
            return maybe_src;

        log::warning(logcat, "Unable to find mapped IPv4 for inbound packet from remote {}", remote);
        return std::nullopt;
    }
    std::optional<ipv6> TunEndpoint::obtain_src_for_ipv6_remote(const NetworkAddress& remote)
    {
        if (auto maybe_src = _local_ipv6_mapping[remote])
            return maybe_src;

        log::warning(logcat, "Unable to find mapped IPv6 for inbound packet from remote {}", remote);
        return std::nullopt;
    }

    void TunEndpoint::send_packet_to_net_if(IPPacket pkt)
    {
        _router._jq->call([this, pkt = std::move(pkt)]() mutable { _net_if->write_packet(std::move(pkt)); });
    }

    void TunEndpoint::rewrite_and_send_packet(IPPacket&& pkt, const ipv4& src, const ipv4& dest)
    {
        pkt.update_ipv4_address(src, dest);
        send_packet_to_net_if(std::move(pkt));
    }
    void TunEndpoint::rewrite_and_send_packet(IPPacket&& pkt, const ipv6& src, const ipv6& dest)
    {
        pkt.update_ipv6_address(src, dest);
        send_packet_to_net_if(std::move(pkt));
    }

    // FIXME: we need separate flags for to-exit and from-exit
    void TunEndpoint::handle_inbound_packet(IPPacket pkt, traffic_type type, NetworkAddress remote)
    {
        (void)type;              // TODO FIXME use this
        bool to_exit = false;    // TODO FIXME
        bool from_exit = false;  // TODO FIXME

        if (to_exit)  // traffic exiting through this node
        {
            log::trace(logcat, "inbound exit pkt for exit node: {}", pkt.info_line());
            if (not is_allowing_traffic(pkt))
            {
                log::warning(logcat, "Dropping inbound exit packet: denied by local traffic policy");
                return;
            }

            if (pkt.is_ipv4())
            {
                if (auto src = obtain_src_for_ipv4_remote(remote))
                    return rewrite_and_send_packet(std::move(pkt), *src, *pkt.dest_ipv4());
            }
            else
            {
                if (auto src = obtain_src_for_ipv6_remote(remote))
                    return rewrite_and_send_packet(std::move(pkt), *src, *pkt.dest_ipv6());
            }
            return;
        }

        if (from_exit)  // return traffic coming back from an exit
        {
            log::trace(logcat, "inbound return exit pkt: {}", pkt.info_line());
            if (pkt.is_ipv4())
                rewrite_and_send_packet(std::move(pkt), *pkt.source_ipv4(), _local_net.ip);
            else
                rewrite_and_send_packet(std::move(pkt), *pkt.source_ipv6(), _local_ipv6_net.ip);
            return;
        }

        log::trace(logcat, "inbound pkt to host: {}", pkt.info_line());
        if (pkt.is_ipv4())
        {
            if (auto src = obtain_src_for_ipv4_remote(remote))
                return rewrite_and_send_packet(std::move(pkt), *src, _local_net.ip);
        }
        else
        {
            if (auto src = obtain_src_for_ipv6_remote(remote))
                return rewrite_and_send_packet(std::move(pkt), *src, _local_ipv6_net.ip);
        }
    }

    void TunEndpoint::start_poller()
    {
        _poller = std::make_unique<ev::FDPoller>(_router.loop(), _net_if->PollFD(), [this] {
            for (auto pkt = _net_if->read_next_packet(); not pkt.empty(); pkt = _net_if->read_next_packet())
            {
                log::trace(logcat, "packet router receiving {}", pkt.info_line());
                _packet_router->handle_ip_packet(std::move(pkt));
            }
        });
        log::debug(logcat, "TUN successfully started FD poller!");
    }

    bool TunEndpoint::is_allowing_traffic(const IPPacket& pkt) const
    {
        return _exit_policy ? _exit_policy->allow_ip_traffic(pkt) : true;
    }

    std::pair<std::optional<ipv4>, std::optional<ipv6>> TunEndpoint::get_mapped_ip(const NetworkAddress& addr)
    {
        return {_local_ipv4_mapping[addr], _local_ipv6_mapping[addr]};
    }

    TunEndpoint::~TunEndpoint() { log::trace(logcat, "TunEndpoint::~TunEndpoint()"); }

}  // namespace srouter::handlers
