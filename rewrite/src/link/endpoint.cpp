#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <sr/link/endpoint.hpp>
#include <sr/link/relay_conn.hpp>

#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

using namespace std::literals;

namespace sr::link
{

    using namespace sr::contact;
    namespace quic = oxen::quic;

    // Connection wrapper — same as upstream srouter::link::Connection
    struct ConnectionInfo
    {
        RouterID rid;
        std::shared_ptr<quic::Connection> conn;
        std::shared_ptr<quic::Datagrams> datagrams;
        std::shared_ptr<quic::BTRequestStream> control_stream;
        std::string alpn;
        bool is_inbound = false;

        void close(uint64_t errcode = 0)
        {
            if (conn)
                conn->close_connection(errcode);
        }
    };

    struct Endpoint::Impl
    {
        std::shared_ptr<quic::Loop> loop;
        std::shared_ptr<quic::Endpoint> ep;
        std::shared_ptr<quic::GNUTLSCreds> tls_creds;
        mutable std::mutex mtx;
        bool is_relay;

        // --- 6-map connection model (matches upstream architecture) ---

        // Established relay-to-relay connections. Relay only.
        // relay_conn tracks both inbound and outbound with winner selection.
        std::unordered_map<RouterID, relay_conn> relay_conns;

        // Tracks relays with both directions connected (for redundancy closing).
        std::unordered_map<RouterID, std::chrono::steady_clock::time_point> relay_bidir;

        // Not-yet-established outbound connections.
        std::unordered_map<RouterID, std::shared_ptr<ConnectionInfo>> pending_outbound;

        // Dead/deregistered relays awaiting disconnect.
        std::unordered_map<RouterID, std::chrono::steady_clock::time_point> pending_dead;

        // Established client-to-relay connections (outbound). Client only.
        std::unordered_map<RouterID, std::shared_ptr<ConnectionInfo>> client_conns;

        // Established inbound client connections. Relay only.
        // Keyed by RouterID (from remote key) for simplicity.
        std::unordered_map<RouterID, std::shared_ptr<ConnectionInfo>> inbound_clients;

        explicit Impl(bool relay) : loop{std::make_shared<quic::Loop>()}, is_relay{relay} {}

        RouterID rid_from_conn(const quic::Connection& c) const
        {
            auto key = c.remote_key();
            sr::crypto::Ed25519PubKey pk{};
            if (key.size() == 32)
                std::memcpy(pk.data(), key.data(), 32);
            return RouterID{pk};
        }

        // Find a ConnectionInfo for a given RouterID across all maps.
        // Returns nullptr if not found.
        ConnectionInfo* find_conn(const RouterID& rid)
        {
            if (is_relay)
            {
                if (auto it = relay_conns.find(rid); it != relay_conns.end() && it->second.conn)
                    return it->second.conn;
                if (auto it = inbound_clients.find(rid); it != inbound_clients.end())
                    return it->second.get();
            }
            else
            {
                if (auto it = client_conns.find(rid); it != client_conns.end())
                    return it->second.get();
            }
            if (auto it = pending_outbound.find(rid); it != pending_outbound.end())
                return it->second.get();
            return nullptr;
        }

        const ConnectionInfo* find_conn(const RouterID& rid) const
        {
            return const_cast<Impl*>(this)->find_conn(rid);
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
                if (!_key_verify)
                    return true;

                if (alpn != "Session_Router_R")
                {
                    if (key.empty() || key.size() == 32)
                        return true;
                    return false;
                }

                if (key.size() != 32)
                    return false;

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
                auto alpn = std::string{c.selected_alpn()};

                if (c.is_inbound())
                {
                    // Create control stream BEFORE any state transfer (critical ordering — W5)
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

                    auto ci = std::make_shared<ConnectionInfo>();
                    ci->rid = rid;
                    ci->conn = c.shared_from_this();
                    ci->datagrams = c.datagrams();
                    ci->control_stream = std::move(ctrl);
                    ci->alpn = alpn;
                    ci->is_inbound = true;

                    std::lock_guard lock{_impl->mtx};

                    if (alpn == "Session_Router_BS")
                    {
                        // Bootstrap connections are untracked (upstream pattern)
                        return;
                    }
                    else if (alpn == "Session_Router_R" && _impl->is_relay)
                    {
                        // Relay inbound → relay_conns with winner selection
                        auto [it, ins] = _impl->relay_conns.emplace(rid, rid < RouterID{_impl->rid_from_conn(c)});
                        it->second.set_conn(std::move(ci), true);
                        if (it->second.outbound)
                            _impl->relay_bidir[rid] = std::chrono::steady_clock::now();
                    }
                    else
                    {
                        // Client inbound → inbound_clients
                        _impl->inbound_clients[rid] = std::move(ci);
                    }
                }
                else
                {
                    // Outbound connection established — move from pending to final map
                    std::lock_guard lock{_impl->mtx};
                    auto pit = _impl->pending_outbound.find(rid);
                    if (pit == _impl->pending_outbound.end())
                        return;

                    auto ci = std::move(pit->second);
                    ci->alpn = alpn;
                    _impl->pending_outbound.erase(pit);

                    if (_impl->is_relay && alpn == "Session_Router_R")
                    {
                        auto [it, ins] = _impl->relay_conns.emplace(rid, rid < RouterID{_impl->rid_from_conn(c)});
                        it->second.set_conn(std::move(ci), false);
                        if (it->second.inbound)
                            _impl->relay_bidir[rid] = std::chrono::steady_clock::now();
                    }
                    else
                    {
                        _impl->client_conns[rid] = std::move(ci);
                    }
                }
            }},
            quic::connection_closed_callback{[this](quic::Connection& c, [[maybe_unused]] uint64_t ec) {
                auto rid = _impl->rid_from_conn(c);
                std::lock_guard lock{_impl->mtx};

                // Check relay_conns
                if (auto it = _impl->relay_conns.find(rid); it != _impl->relay_conns.end())
                {
                    auto& rc = it->second;
                    if (rc.inbound && rc.inbound->conn && rc.inbound->conn == c.shared_from_this())
                        rc.close(true);
                    if (rc.outbound && rc.outbound->conn && rc.outbound->conn == c.shared_from_this())
                        rc.close(false);
                    if (!rc.conn)
                    {
                        _impl->relay_conns.erase(it);
                        _impl->relay_bidir.erase(rid);
                    }
                    return;
                }

                // Check pending_outbound
                _impl->pending_outbound.erase(rid);

                // Check client_conns
                _impl->client_conns.erase(rid);

                // Check inbound_clients
                _impl->inbound_clients.erase(rid);
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

        auto ci = std::make_shared<ConnectionInfo>();
        ci->rid = rid;
        ci->conn = conn;
        ci->datagrams = conn->datagrams();
        ci->control_stream = std::move(ctrl);
        ci->alpn = _is_relay ? "Session_Router_R" : "Session_Router_C";
        ci->is_inbound = false;

        {
            std::lock_guard lock{_impl->mtx};
            _impl->pending_outbound[rid] = std::move(ci);
        }
    }

    void Endpoint::send_datagram(const RouterID& to, std::span<const std::byte> data)
    {
        std::lock_guard lock{_impl->mtx};
        auto* ci = _impl->find_conn(to);
        if (!ci || !ci->datagrams)
            return;
        std::vector<std::byte> buf(data.begin(), data.end());
        ci->datagrams->send(std::move(buf));
    }

    void Endpoint::send_request(
        const RouterID& to,
        std::string_view method,
        std::span<const std::byte> payload,
        std::function<void(std::span<const std::byte>)> on_response)
    {
        std::lock_guard lock{_impl->mtx};
        auto* ci = _impl->find_conn(to);
        if (!ci || !ci->control_stream)
            return;

        std::string ep_name{method};

        if (on_response)
        {
            ci->control_stream->command(
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
            ci->control_stream->command(std::move(ep_name), payload);
        }
    }

    void Endpoint::on_datagram(DatagramHandler handler) { _dgram_handler = std::move(handler); }

    void Endpoint::on_request(BTStreamHandler handler) { _bt_handler = std::move(handler); }

    void Endpoint::set_key_verify(KeyVerifyCallback callback) { _key_verify = std::move(callback); }

    bool Endpoint::is_connected(const RouterID& to) const
    {
        std::lock_guard lock{_impl->mtx};
        return _impl->find_conn(to) != nullptr;
    }

    size_t Endpoint::connection_count() const
    {
        std::lock_guard lock{_impl->mtx};
        size_t count = _impl->relay_conns.size()
            + _impl->client_conns.size()
            + _impl->inbound_clients.size()
            + _impl->pending_outbound.size();
        return count;
    }

    std::vector<RouterID> Endpoint::connected_peers() const
    {
        std::lock_guard lock{_impl->mtx};
        std::vector<RouterID> peers;
        for (const auto& [rid, _] : _impl->relay_conns)
            peers.push_back(rid);
        for (const auto& [rid, _] : _impl->client_conns)
            peers.push_back(rid);
        for (const auto& [rid, _] : _impl->inbound_clients)
            peers.push_back(rid);
        for (const auto& [rid, _] : _impl->pending_outbound)
            peers.push_back(rid);
        return peers;
    }

    void Endpoint::disconnect(const RouterID& rid)
    {
        std::lock_guard lock{_impl->mtx};

        if (auto it = _impl->relay_conns.find(rid); it != _impl->relay_conns.end())
        {
            it->second.close_all();
            _impl->relay_conns.erase(it);
            _impl->relay_bidir.erase(rid);
            return;
        }
        if (auto it = _impl->pending_outbound.find(rid); it != _impl->pending_outbound.end())
        {
            it->second->close();
            _impl->pending_outbound.erase(it);
            return;
        }
        if (auto it = _impl->client_conns.find(rid); it != _impl->client_conns.end())
        {
            it->second->close();
            _impl->client_conns.erase(it);
            return;
        }
        if (auto it = _impl->inbound_clients.find(rid); it != _impl->inbound_clients.end())
        {
            it->second->close();
            _impl->inbound_clients.erase(it);
            return;
        }
    }

    std::string Endpoint::connection_alpn(const RouterID& rid) const
    {
        std::lock_guard lock{_impl->mtx};
        auto* ci = _impl->find_conn(rid);
        if (!ci)
            return {};
        return ci->alpn;
    }

    bool Endpoint::is_inbound_connection(const RouterID& rid) const
    {
        std::lock_guard lock{_impl->mtx};
        auto* ci = _impl->find_conn(rid);
        if (!ci)
            return false;
        return ci->is_inbound;
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
            {
                std::lock_guard lock{_impl->mtx};
                // Ordered shutdown (upstream pattern):
                // 1. Relay connections
                for (auto& [_, rc] : _impl->relay_conns)
                    rc.close_all();
                _impl->relay_conns.clear();
                _impl->relay_bidir.clear();

                // 2. Pending outbound
                for (auto& [_, ci] : _impl->pending_outbound)
                    ci->close();
                _impl->pending_outbound.clear();

                // 3. Client connections
                for (auto& [_, ci] : _impl->client_conns)
                    ci->close();
                _impl->client_conns.clear();

                // 4. Inbound clients
                for (auto& [_, ci] : _impl->inbound_clients)
                    ci->close();
                _impl->inbound_clients.clear();

                // 5. Dead tracking
                _impl->pending_dead.clear();
            }
            _impl->ep->close_conns();
            _impl->ep.reset();
        }
    }

}  // namespace sr::link
