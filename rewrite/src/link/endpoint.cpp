#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <sr/link/endpoint.hpp>

#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

using namespace std::literals;

namespace sr::link
{

    using namespace sr::contact;
    namespace quic = oxen::quic;

    struct ConnectionInfo
    {
        RouterID rid;
        std::shared_ptr<quic::Connection> conn;
        std::shared_ptr<quic::Datagrams> datagrams;
        std::shared_ptr<quic::BTRequestStream> control_stream;
        std::string alpn;  // Selected ALPN for this connection
        bool is_inbound = false;
    };

    struct Endpoint::Impl
    {
        std::shared_ptr<quic::Loop> loop;
        std::shared_ptr<quic::Endpoint> ep;
        std::shared_ptr<quic::GNUTLSCreds> tls_creds;
        mutable std::mutex mtx;
        std::unordered_map<RouterID, ConnectionInfo> connections;
        bool is_relay;

        explicit Impl(bool relay) : loop{std::make_shared<quic::Loop>()}, is_relay{relay} {}

        RouterID rid_from_conn(const quic::Connection& c) const
        {
            auto key = c.remote_key();
            sr::crypto::Ed25519PubKey pk{};
            if (key.size() == 32)
                std::memcpy(pk.data(), key.data(), 32);
            return RouterID{pk};
        }
    };

    Endpoint::Endpoint(bool is_relay) : _is_relay{is_relay}, _impl{std::make_unique<Impl>(is_relay)} {}

    Endpoint::~Endpoint() { close(); }

    void Endpoint::listen(
        uint16_t port, std::span<const std::byte, 32> ed_seed, std::span<const std::byte, 32> ed_pubkey)
    {
        _impl->tls_creds = quic::GNUTLSCreds::make_from_ed_keys(
            std::string_view{reinterpret_cast<const char*>(ed_seed.data()), 32},
            std::string_view{reinterpret_cast<const char*>(ed_pubkey.data()), 32});

        _impl->tls_creds->request_client_keys(
            [this](std::span<const uint8_t> key, std::string_view alpn) -> bool {
                // If no key verify callback set, accept all (testing/permissive mode)
                if (!_key_verify)
                    return true;

                // Non-relay connections: accept if no key or valid size
                if (alpn != "Session_Router_R")
                {
                    if (key.empty() || key.size() == 32)
                        return true;
                    return false;  // Wrong key size
                }

                // Relay connections MUST provide a valid 32-byte key
                if (key.size() != 32)
                    return false;

                // Build RouterID from key and check with callback
                sr::crypto::Ed25519PubKey pk{};
                std::memcpy(pk.data(), key.data(), 32);
                sr::contact::RouterID rid{pk};

                return _key_verify(rid, alpn);
            });

        auto in_alpns = _is_relay
            ? quic::opt::inbound_alpns{"Session_Router_R", "Session_Router_C", "Session_Router_BS"}
            : quic::opt::inbound_alpns{"Session_Router_C"};

        auto out_alpns =
            _is_relay ? quic::opt::outbound_alpns{"Session_Router_R"} : quic::opt::outbound_alpns{"Session_Router_C"};

        _impl->ep = quic::Endpoint::endpoint(
            *_impl->loop,
            quic::Address{port},
            quic::opt::enable_datagrams{quic::Splitting::ACTIVE}.queue_limit(2'000'000),
            std::move(in_alpns),
            std::move(out_alpns),
            quic::connection_established_callback{[this](quic::Connection& c) {
                auto rid = _impl->rid_from_conn(c);

                if (c.is_inbound())
                {
                    auto ctrl = c.queue_incoming_stream<quic::BTRequestStream>();
                    if (_bt_handler)
                    {
                        ctrl->register_generic_handler([this, rid](quic::message msg) {
                            auto ep_name = std::string{msg.endpoint()};
                            auto body = msg.body<std::byte>();
                            std::span<const std::byte> body_span{body.data(), body.size()};
                            _bt_handler(
                                rid, ep_name, body_span, [m = std::move(msg)](std::vector<std::byte> resp) mutable {
                                    m.respond(
                                        std::string_view{reinterpret_cast<const char*>(resp.data()), resp.size()});
                                });
                        });
                    }

                    std::lock_guard lock{_impl->mtx};
                    auto& ci = _impl->connections[rid];
                    ci.rid = rid;
                    ci.conn = c.shared_from_this();
                    ci.datagrams = c.datagrams();
                    ci.control_stream = std::move(ctrl);
                    ci.alpn = std::string{c.selected_alpn()};
                    ci.is_inbound = true;
                }
            }},
            quic::connection_closed_callback{[this](quic::Connection& c, [[maybe_unused]] uint64_t ec) {
                auto rid = _impl->rid_from_conn(c);
                std::lock_guard lock{_impl->mtx};
                _impl->connections.erase(rid);
            }},
            quic::dgram_data_callback{[this](quic::datagram dg) {
                if (_dgram_handler)
                {
                    auto rid = _impl->rid_from_conn(dg.conn);
                    _dgram_handler(rid, dg.data);
                }
            }});

        _impl->ep->listen(_impl->tls_creds);
    }

    void Endpoint::connect(const RouterID& rid, const std::string& addr, uint16_t port)
    {
        auto remote = quic::RemoteAddress{{reinterpret_cast<const unsigned char*>(rid.data()), 32}, addr, port};

        auto conn =
            _impl->ep->connect(remote, _impl->tls_creds, quic::opt::keep_alive{10s}, quic::opt::idle_timeout{60s});

        auto ctrl = conn->open_stream<quic::BTRequestStream>();

        {
            std::lock_guard lock{_impl->mtx};
            auto& ci = _impl->connections[rid];
            ci.rid = rid;
            ci.conn = conn;
            ci.datagrams = conn->datagrams();
            ci.control_stream = std::move(ctrl);
            ci.alpn = _is_relay ? "Session_Router_R" : "Session_Router_C";
            ci.is_inbound = false;
        }
    }

    void Endpoint::send_datagram(const RouterID& to, std::span<const std::byte> data)
    {
        std::lock_guard lock{_impl->mtx};
        auto it = _impl->connections.find(to);
        if (it == _impl->connections.end() || !it->second.datagrams)
            return;
        std::vector<std::byte> buf(data.begin(), data.end());
        it->second.datagrams->send(std::move(buf));
    }

    void Endpoint::send_request(
        const RouterID& to,
        std::string_view method,
        std::span<const std::byte> payload,
        std::function<void(std::span<const std::byte>)> on_response)
    {
        std::lock_guard lock{_impl->mtx};
        auto it = _impl->connections.find(to);
        if (it == _impl->connections.end() || !it->second.control_stream)
            return;

        std::string ep_name{method};

        if (on_response)
        {
            it->second.control_stream->command(
                std::move(ep_name), payload, [cb = std::move(on_response)](quic::message msg) {
                    if (msg)
                    {
                        auto body = msg.body<std::byte>();
                        cb({body.data(), body.size()});
                    }
                });
        }
        else
        {
            it->second.control_stream->command(std::move(ep_name), payload);
        }
    }

    void Endpoint::on_datagram(DatagramHandler handler) { _dgram_handler = std::move(handler); }

    void Endpoint::on_request(BTStreamHandler handler) { _bt_handler = std::move(handler); }

    void Endpoint::set_key_verify(KeyVerifyCallback callback) { _key_verify = std::move(callback); }

    bool Endpoint::is_connected(const RouterID& to) const
    {
        std::lock_guard lock{_impl->mtx};
        return _impl->connections.contains(to);
    }

    size_t Endpoint::connection_count() const
    {
        std::lock_guard lock{_impl->mtx};
        return _impl->connections.size();
    }

    std::vector<RouterID> Endpoint::connected_peers() const
    {
        std::lock_guard lock{_impl->mtx};
        std::vector<RouterID> peers;
        peers.reserve(_impl->connections.size());
        for (const auto& [rid, _] : _impl->connections)
            peers.push_back(rid);
        return peers;
    }

    void Endpoint::disconnect(const RouterID& rid)
    {
        std::lock_guard lock{_impl->mtx};
        auto it = _impl->connections.find(rid);
        if (it != _impl->connections.end())
        {
            if (it->second.conn)
                it->second.conn->close_connection();
            _impl->connections.erase(it);
        }
    }

    std::string Endpoint::connection_alpn(const RouterID& rid) const
    {
        std::lock_guard lock{_impl->mtx};
        auto it = _impl->connections.find(rid);
        if (it == _impl->connections.end())
            return {};
        return it->second.alpn;
    }

    bool Endpoint::is_inbound_connection(const RouterID& rid) const
    {
        std::lock_guard lock{_impl->mtx};
        auto it = _impl->connections.find(rid);
        if (it == _impl->connections.end())
            return false;
        return it->second.is_inbound;
    }

    uint16_t Endpoint::local_port() const
    {
        if (_impl && _impl->ep)
            return _impl->ep->local().port();
        return 0;
    }

    void Endpoint::close()
    {
        if (_impl && _impl->ep)
        {
            // Clear connections first (under lock) to prevent callbacks from accessing stale state
            {
                std::lock_guard lock{_impl->mtx};
                _impl->connections.clear();
            }
            // Close connections and endpoint (may trigger callbacks, but connections map is empty)
            _impl->ep->close_conns();
            _impl->ep.reset();
        }
    }

}  // namespace sr::link
