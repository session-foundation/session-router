#include "endpoint.hpp"

#include "link_manager.hpp"
#include "nodedb.hpp"
#include "util/bspan.hpp"
#include "util/time.hpp"

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/connection_ids.hpp>
#include <oxen/quic/context.hpp>  // TODO FIXME: can't construct an Endpoint without this!
#include <oxen/quic/opt.hpp>
#include <sodium/crypto_generichash_blake2b.h>

#include <chrono>

namespace srouter::link
{
    static auto logcat = log::Cat("link.endpoint");

    void relay_conn::set_conn(std::shared_ptr<link::Connection> c, bool is_inbound)
    {
        auto& ptr = is_inbound ? inbound : outbound;
        if (ptr)
            ptr->close();
        ptr = std::move(c);

        if (is_inbound ? not outbound or inbound_wins : not inbound or not inbound_wins)
            conn = ptr.get();
    }

    void relay_conn::close(bool direction_inbound, uint64_t errcode)
    {
        auto& to_close = direction_inbound ? inbound : outbound;
        if (not to_close)
            return;

        to_close->close(errcode);
        to_close.reset();

        // Switch preferred conn to the other direction (will be nullptr if the other direction
        // isn't established):
        conn = (direction_inbound ? outbound : inbound).get();
    }

    void relay_conn::close_all(uint64_t errcode)
    {
        if (inbound)
            inbound->close(errcode);
        if (outbound)
            outbound->close(errcode);
        inbound = outbound = nullptr;
        conn = nullptr;
    }

    void relay_conn::close_redundant() { close(not inbound_wins, CONN_CLOSE_REDUNDANT); }

    static std::vector<uint8_t> make_static_secret(
        const Ed25519SecretKey& sk, std::string_view static_secret_key = "Session Router static shared secret key"sv)
    {
        std::vector<uint8_t> secret;
        secret.resize(32);

        crypto_generichash_blake2b_state st;
        crypto_generichash_blake2b_init(
            &st, reinterpret_cast<const uint8_t*>(static_secret_key.data()), static_secret_key.size(), secret.size());
        crypto_generichash_blake2b_update(&st, sk.udata(), sk.size());
        crypto_generichash_blake2b_final(&st, secret.data(), secret.size());

        return secret;
    }

    Endpoint::Endpoint(Manager& lm)
        : manager{lm},
          router{lm.router},
          loop{std::make_unique<quic::Loop>()},
          tls_creds{
              router.is_service_node ? quic::GNUTLSCreds::make_from_ed_keys(
                                           {reinterpret_cast<const char*>(router.secret_key().data()), 32},
                                           {reinterpret_cast<const char*>(router.id().data()), 32})
                                     : quic::GNUTLSCreds::make_unauthenticated()}
    {
        std::optional<quic::opt::inbound_alpns> inbound_alpn;
        if (router.is_service_node)
            inbound_alpn.emplace({RELAY_ALPN, CLIENT_ALPN, BOOTSTRAP_ALPN});

        std::optional<quic::opt::max_udp_payload> max_udp_payload;
        if (auto cap = router.config().links.max_udp_payload)
            max_udp_payload.emplace(*cap);

        endpoint = quic::Endpoint::endpoint(
            *loop,
            router.listen_addr(),
            quic::opt::static_secret{make_static_secret(router.secret_key())},
            [this](quic::Connection& conn) { on_conn_established(conn); },
            [this](quic::Connection& conn, uint64_t ec) { on_conn_closed(conn, ec); },
            [this](quic::datagram dgram) {
                // Transfer handling to the router loop:
                router._jq->call([this, msg = std::move(dgram).extract()]() mutable {
                    manager.handle_session_message(std::move(msg));
                });
            },
            inbound_alpn,
            quic::opt::outbound_alpns{{router.is_service_node ? RELAY_ALPN : CLIENT_ALPN}},
            quic::opt::enable_datagrams{quic::Splitting::ACTIVE}.queue_limit(2'000'000),
            max_udp_payload);

        tls_creds->enable_outbound_0rtt(
            [this](
                const quic::RemoteAddress& remote, std::vector<unsigned char> data, std::chrono::sys_seconds expiry) {
                RouterID rid;
                if (remote.view_remote_key().size() != RouterID::SIZE)
                {
                    log::warning(
                        logcat,
                        "Not storing 0RTT ticker: unexpected remote pubkey size {}",
                        remote.view_remote_key().size());
                    return;
                }
                rid.assign(remote.view_remote_key().first<RouterID::SIZE>());
                router.node_db().store_0rtt(rid, std::move(data), expiry);
            },
            [this](const quic::RemoteAddress& remote) {
                std::optional<std::vector<unsigned char>> ret;
                if (remote.view_remote_key().size() != RouterID::SIZE)
                    return ret;
                RouterID rid{remote.view_remote_key().first<RouterID::SIZE>()};
                ret = router.node_db().extract_0rtt(rid);
                return ret;
            });

        if (router.is_service_node)
        {
            tls_creds->enable_inbound_0rtt(0s, 48h);

            tls_creds->request_client_keys([this](const std::span<const uint8_t> key, const std::string_view alpn) {
                // NB: this code *must not* call_get into the router event loop, because there are
                // lots of places that router call-get's into endloop.loop, and so any attempt to
                // call-get the other direction is a recipe for deadlock.

                if (alpn != RELAY_ALPN)
                {
                    // For non-relay (i.e. client or bootstrap) conns we don't need a key, but if
                    // they provided one, it has to at least be of the correct size for an Ed25519
                    // pubkey.
                    if (key.empty() || key.size() == PubKey::SIZE)
                        return true;

                    log::warning(
                        logcat,
                        "Rejecting incoming {} connection with invalid optional pubkey ({} bytes, expected {})",
                        alpn,
                        key.size(),
                        RouterID::SIZE);
                    return false;
                }

                // Otherwise the incoming conn is from a relay: we only request client keys, but if
                // the incoming connection is a relay (using the relay ALPN) then it must provide
                // one:
                if (key.size() != RouterID::SIZE)
                {
                    log::warning(
                        logcat,
                        "Rejecting incoming {} connection with missing or invalid pubkey ({} bytes, expected {})",
                        alpn,
                        key.size(),
                        RouterID::SIZE);
                    return false;
                }
                RouterID other{key.first<RouterID::SIZE>()};

                if (other == router.id())
                {
                    log::error(
                        logcat,
                        "Rejecting incoming relay connection from relay with our own key ({})",
                        other.to_network_address());
                    return false;
                }

                if (router.node_db().is_registered(other))
                    return true;

                log::warning(logcat, "Rejecting incoming relay connection from unregistered RID {}", other);
                return false;
            });

            endpoint->listen(
                tls_creds,
                quic::opt::idle_timeout{router.is_service_node ? RELAY_INBOUND_IDLE_TIMEOUT : CLIENT_IDLE_TIMEOUT});
        }
    }

    void Endpoint::start_timers()
    {
        if (router.is_service_node)
        {
            redundancy_timer = router._jq->add_timer(REDUNDANT_LINGER, [this] { close_redundant(); });
            dereg_conn_timer = router._jq->add_timer(1min, [this] { check_deregged_conns(); });
        }
    }

    link::Connection* Endpoint::get_relay_conn(const RouterID& relay) const
    {
        return router._jq->call_get([this, relay]() -> link::Connection* {
            if (router.is_service_node)
            {
                if (auto it = relay_conns.find(relay); it != relay_conns.end())
                    return it->second.conn;
            }
            else if (auto it = client_conns.find(relay); it != client_conns.end())
                return it->second.get();

            return nullptr;
        });
    }

    void Endpoint::close_redundant(sys_ms now)
    {
        for (auto it = relay_bidir.begin(); it != relay_bidir.end();)
        {
            auto& [rid, since] = *it;
            if (now >= since + REDUNDANT_LINGER)
            {
                auto rcit = relay_conns.find(rid);
                // If this assertion fails then something else in here isn't cleaning up properly:
                assert(rcit != relay_conns.end() and rcit->second.inbound and rcit->second.outbound);
                rcit->second.close_redundant();
                it = relay_bidir.erase(it);
            }
            else
                ++it;
        }
    }

    void Endpoint::check_deregged_conns()
    {
        assert(router.is_service_node);

        auto now = std::chrono::steady_clock::now();

        auto registered = router.node_db().get_registered_relay_set();

        // Look for any pending dead that have been dead long enough to disconnect from:
        for (auto it = pending_dead.begin(); it != pending_dead.end();)
        {
            const auto& [rid, dead_since] = *it;

            // -1s because this only fires every 1min and the -1s prevents tiny variations in the
            // clock from "missing" the threshold and pushing to 31min instead of 30min.
            if (dead_since + DEREGGED_LINGER > now - 1s)
            {
                // Not dead long enough
                ++it;
                continue;
            }

            if (registered.contains(rid))
            {
                // Became registered again somehow
                log::debug(logcat, "Not disconnecting from previously de-regged {}.snode: it is registered again", rid);
                it = pending_dead.erase(it);
                continue;
            }

            if (auto rcit = relay_conns.find(rid); rcit != relay_conns.end())
            {
                rcit->second.close_all();
                relay_conns.erase(rcit);
                if (auto pit = pending_outbound.find(rid); pit != pending_outbound.end())
                {
                    if (pit->second)
                        pit->second->close();
                    pending_outbound.erase(pit);
                }
                relay_bidir.erase(rid);
                log::debug(logcat, "Dropped connection to deregistered node {}", rid);
            }
            else
                log::debug(logcat, "Connection to deregged node {} is already dropped", rid);

            it = pending_dead.erase(it);
        }

        // Record timestamps for any newly unregistered nodes so that, when the timer expires, we
        // drop the connection.
        for (const auto& [rid, rconn] : relay_conns)
            if (!registered.contains(rid) && pending_dead.emplace(rid, now).second)
                log::debug(
                    logcat, "Relay {} is no longer registered; scheduling disconnect in {}", rid, DEREGGED_LINGER);
    }

    link::Connection* Endpoint::get_client_conn(const RouterID& remote) const
    {
        if (router.is_service_node)
            return nullptr;
        return router._jq->call_get([this, remote]() -> link::Connection* {
            if (auto itr = client_conns.find(remote); itr != client_conns.end())
                return itr->second.get();
            return nullptr;
        });
    }

    void Endpoint::for_each_relay_conn(std::function<void(const RouterID&, link::Connection&)> func) const
    {
        assert(router.loop().inside());

        if (manager.is_stopping)
            return;

        for (const auto& [rid, relay] : relay_conns)
        {
            assert(relay.conn);
            func(rid, *relay.conn);
        }
    }

    std::unordered_set<RouterID> Endpoint::get_current_relays(bool include_pending) const
    {
        std::unordered_set<RouterID> ret;

        if (router.is_service_node)
        {
            for (auto& [rid, conn] : relay_conns)
            {
                assert(conn.conn);  // nullptr means something left a bad conn in here instead of clearing it out
                ret.insert(rid);
            }
        }
        else
        {
            for (auto& [rid, conn] : client_conns)
            {
                assert(conn);
                ret.insert(rid);
            }
        }
        if (include_pending)
        {
            for (auto& [rid, c] : pending_outbound)
            {
                assert(c);
                ret.insert(rid);
            }
        }

        return ret;
    }

    std::optional<quic::ipv4_net> Endpoint::unique_edge_range() const
    {
        std::optional<quic::ipv4_net> network;

        auto mask = router.config().paths.unique_hop_netmask;
        if (not mask or router.is_service_node)
            return network;

        for (auto& [rid, conn] : client_conns)
        {
            auto ip = conn->conn->remote().to_ipv4();
            if (not network)
                network = ip % mask;
            else if (not network->contains(ip))
            {
                // There are at least two different networks
                network.reset();
                break;
            }
        }
        return network;
    }

    bool Endpoint::connected_to_relay(const RouterID& relay, bool include_pending) const
    {
        if (router.is_service_node ? relay_conns.contains(relay) : client_conns.contains(relay))
            return true;
        if (include_pending and pending_outbound.contains(relay))
            return true;
        return false;
    }

    void Endpoint::shutdown()
    {
        log::debug(logcat, "Closing all connections");
        for (auto& [rid, conn] : relay_conns)
            conn.close_all();
        relay_conns.clear();
        relay_bidir.clear();

        for (auto& conn : pending_outbound | std::views::values)
            conn->close();
        pending_outbound.clear();

        for (auto& conn : client_conns | std::views::values)
            conn->close();
        client_conns.clear();

        for (auto& conn : inbound_clients | std::views::values)
            conn->close();
        inbound_clients.clear();

        log::debug(logcat, "Closing quic endpoint");
        endpoint.reset();

        log::info(logcat, "Stopping network endpoint event loop");
        loop.reset();
    }

    std::array<int, 5> Endpoint::relay_connection_counts() const
    {
        if (not router.is_service_node)
            return {0};
        return router._jq->call_get([this] {
            std::array<int, 5> result{0};
            auto& [relays, out, in, pending, clients] = result;

            relays = static_cast<int>(relay_conns.size());
            clients = static_cast<int>(inbound_clients.size());
            pending = static_cast<int>(pending_outbound.size());
            for (const auto& c : std::views::values(relay_conns))
            {
                if (c.inbound)
                    ++in;
                if (c.outbound)
                    ++out;
            }

            return result;
        });
    }

    std::array<int, 2> Endpoint::client_connection_counts() const
    {
        return router._jq->call_get([this] {
            return std::array{static_cast<int>(client_conns.size()), static_cast<int>(pending_outbound.size())};
        });
    }

    int Endpoint::num_relay_conns(bool include_pending) const
    {
        return router._jq->call_get([this, &include_pending] {
            int c;
            if (router.is_service_node)
            {
                c = static_cast<int>(relay_conns.size());
                if (include_pending)
                    // Check each pending conn instead of just adding pending_outbound.count() because
                    // we don't want to double count a relay if we have a pending outbound connection
                    // to a relay with which we have already established an inbound connection:
                    for (auto& [rid, conn] : pending_outbound)
                        if (!relay_conns.contains(rid))
                            c++;
            }
            else
            {
                // We are a client, and so *all* connections are outbound to a relay that we
                // initiated: Unlike the above, we would never initiate to an already pending or
                // already connected node, so don't have to worry about duplicates.
                c = static_cast<int>(client_conns.size() + (include_pending ? pending_outbound.size() : 0));
            }
            return c;
        });
    }

    std::pair<bool, quic::BTRequestStream*> Endpoint::ctrl_stream_impl(const RelayContact& rc)
    {
        assert(router.loop().inside());
        std::pair<bool, quic::BTRequestStream*> result;
        auto& [res_est, res_str] = result;

        auto rid = rc.router_id();

        if (auto* c = get_relay_conn(rid))
        {
            res_est = true;
            res_str = c->control_stream.get();
            return result;
        }

        res_est = false;
        auto& pending = pending_outbound[rid];
        if (!pending)
        {
            log::debug(logcat, "Initiating new connection to send to {}", rid.short_string());
            auto conn = endpoint->connect(
                quic::RemoteAddress{rid.to_view(), rc.addr()},
                tls_creds,
                quic::opt::keep_alive{router.is_service_node ? RELAY_OUTBOUND_KEEP_ALIVE : CLIENT_KEEP_ALIVE},
                quic::opt::idle_timeout{router.is_service_node ? RELAY_OUTBOUND_IDLE_TIMEOUT : CLIENT_IDLE_TIMEOUT});

            auto control_stream = make_control(*conn, rid, router.is_service_node ? RELAY_ALPN : CLIENT_ALPN);

            pending = std::make_shared<Connection>(std::move(conn), std::move(control_stream));
        }
        res_str = pending->control_stream.get();

        return result;
    }

    bool Endpoint::ensure_connection(const RelayContact& rc)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        return ctrl_stream_impl(rc).first;
    }

    quic::BTRequestStream& Endpoint::control_stream_for(const RelayContact& rc)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        return *ctrl_stream_impl(rc).second;
    }

    void Endpoint::send_command(
        const RelayContact& rc,
        std::string endpoint,
        std::vector<std::byte> body,
        std::function<void(quic::message)> response_handler)
    {
        if (manager.is_stopping)
            return;

        if (response_handler)
            // Wrap the handler to transfer to the router loop for execution:
            response_handler = [f = std::move(response_handler), &rloop = router.loop()](quic::message m) mutable {
                rloop.call([f = std::move(f), m = std::move(m)]() mutable { f(std::move(m)); });
            };

        control_stream_for(rc).command(std::move(endpoint), std::move(body), std::move(response_handler));
    }

    bool Endpoint::send_command(
        const RouterID& rid,
        std::string endpoint,
        std::vector<std::byte> body,
        std::function<void(quic::message)> response_handler)
    {
        if (manager.is_stopping)
            return false;

        auto* rc = router.node_db().get_rc(rid);
        if (!rc)
        {
            log::error(
                logcat, "Unable to send {} control command to {}: RC not found", endpoint, rid.to_network_address());
            return false;
        }

        send_command(*rc, std::move(endpoint), std::move(body), std::move(response_handler));
        return true;
    }

    bool Endpoint::send_command(
        const quic::ConnectionID& client_cid,
        std::string endpoint,
        std::vector<std::byte> body,
        std::function<void(quic::message)> response_handler)
    {
        assert(router.is_service_node);
        if (manager.is_stopping)
            return false;

        auto it = inbound_clients.find(client_cid);
        if (it == inbound_clients.end())
        {
            log::debug(
                logcat, "Unable to send {} control command to client[{}]: connection not found", endpoint, client_cid);
            return false;
        }

        auto& conn = it->second;
        if (!conn || conn->conn->is_closing())
        {
            log::debug(
                logcat, "Unable to send {} control command to client[{}]: connection is closing", endpoint, client_cid);
            return false;
        }

        if (response_handler)
            // Wrap the handler to transfer to the router loop for execution:
            response_handler = [f = std::move(response_handler), &rloop = router.loop()](quic::message m) mutable {
                rloop.call([f = std::move(f), m = std::move(m)]() mutable { f(std::move(m)); });
            };

        conn->control_stream->command(std::move(endpoint), std::move(body), std::move(response_handler));
        return true;
    }

    bool Endpoint::send_datagram(const RouterID& relay, std::vector<std::byte> body)
    {
        if (manager.is_stopping)
            return false;

        if (auto* conn = get_relay_conn(relay))
        {
            conn->datagrams->send(std::move(body));
            return true;
        }

        // Unlike send_command, if we don't have an established connection yet then we simply
        // drop this rather than trying to store it in a queue.
        return false;
    }

    bool Endpoint::send_datagram(const quic::ConnectionID& cid, std::vector<std::byte> body)
    {
        if (manager.is_stopping)
            return false;

        auto it = inbound_clients.find(cid);
        if (it == inbound_clients.end())
            return false;

        auto& conn = *it->second;
        conn.datagrams->send(std::move(body));
        return true;
    }

    std::shared_ptr<quic::BTRequestStream> Endpoint::make_control(
        quic::Connection& conn, std::span<const std::byte> remote_key, std::string_view alpn)
    {
        std::shared_ptr<quic::BTRequestStream> control_stream;

        std::variant<RouterID, quic::ConnectionID> remote{conn.reference_id()};
        if (alpn == RELAY_ALPN)
        {
            assert(remote_key.size() == RouterID::SIZE);
            remote.emplace<RouterID>(remote_key.first<RouterID::SIZE>());
        }

        if (conn.is_inbound())
        {
            assert(router.is_service_node);
            control_stream =
                conn.template queue_incoming_stream<quic::BTRequestStream>([](quic::Stream&, uint64_t error_code) {
                    log::warning(logcat, "BTRequestStream closed unexpectedly (ec:{})", error_code);
                });

            log::trace(logcat, "Queued BTStream to be opened (ID:{})", control_stream->stream_id());
            assert(control_stream->stream_id() == 0);

            if (alpn == BOOTSTRAP_ALPN)
            {
                assert(router.is_service_node);  // A client should never be receiving an *inbound*
                                                 // bootstrap ALPN connection.
                manager.register_bootstrap_commands(*control_stream);
            }
        }
        else
        {
            control_stream = conn.open_stream<quic::BTRequestStream>(
                [](quic::Stream&, uint64_t error_code) {
                    log::warning(logcat, "BTRequestStream closed unexpectedly (ec:{})", error_code);
                },
                quic::opt::stream_notify);

            log::trace(logcat, "Opened BTStream (ID:{})", control_stream->stream_id());
        }

        if (alpn != BOOTSTRAP_ALPN)
            manager.register_commands(*control_stream, remote);

        return control_stream;
    }

    static auto log_bs = log::Cat("bootstrap");
    void Endpoint::on_inbound_conn(
        std::shared_ptr<quic::Connection> qconn, std::shared_ptr<quic::BTRequestStream> control)
    {
        assert(router.is_service_node);

        std::optional<RouterID> rid;
        if (not qconn->remote_key().empty())
        {
            assert(
                qconn->remote_key().size() == RouterID::SIZE);  // Should have been checked in the key verify callback
            rid.emplace(qconn->remote_key().first<RouterID::SIZE>());
        }

        auto alpn = qconn->selected_alpn();
        if (alpn == BOOTSTRAP_ALPN)
        {
            log::debug(log_bs, "New incoming bootstrap connection from {}", qconn->remote());
            return;
        }

        auto conn = std::make_shared<link::Connection>(std::move(qconn), std::move(control));
        if (alpn == RELAY_ALPN)
        {
            assert(rid);  // key verification should have enforced this
            auto [it, ins] = relay_conns.emplace(*rid, *rid < router.id());
            auto& relcon = it->second;
            assert(ins ? !relcon.conn : !!relcon.conn);
            bool already_had_inbound{relcon.inbound};
            relcon.set_conn(std::move(conn), true);
            if (relcon.outbound)
                relay_bidir[*rid] = srouter::time_now_ms();

            log::debug(
                logcat,
                "{} incoming relay connection from {} ({} outbound connection)",
                already_had_inbound ? "Replaced existing" : "New",
                rid->to_network_address(true),
                !relcon.outbound          ? "no current"
                    : relcon.inbound_wins ? "have redundant"
                                          : "have more-preferred");
        }
        else
        {
            // We are a service node, and so we use this container to holds client connections to us:
            log::debug(logcat, "New incoming client connection from {}", conn->conn->remote());
            auto& cid = conn->conn->reference_id();
            inbound_clients.emplace(cid, std::move(conn));
        }
    }

    void Endpoint::on_outbound_conn(std::shared_ptr<quic::Connection> qconn)
    {
        assert(qconn->remote_key().size() == RouterID::SIZE);
        RouterID rid{qconn->remote_key().first<RouterID::SIZE>()};

        assert(router.is_service_node == (qconn->selected_alpn() != CLIENT_ALPN));

        auto pit = pending_outbound.find(rid);
        if (pit == pending_outbound.end())
        {
            log::error(logcat, "Internal error: outbound connection completed without a pending connection");
            return;
        }

        if (router.is_service_node)
        {
            auto [it, ins] = relay_conns.emplace(rid, rid < router.id());
            auto& relcon = it->second;
            assert(ins ? !relcon.conn : !!relcon.conn);
            bool already_had_outbound{relcon.outbound};
            if (already_had_outbound)
                log::error(
                    logcat, "Internal error: duplicate outbound connection established, but that shouldn't happen");

            relcon.set_conn(std::move(pit->second), false);
            if (relcon.inbound)
                relay_bidir[rid] = srouter::time_now_ms();

            log::debug(
                logcat,
                "{} outbound connection to {} ({} inbound connection)",
                already_had_outbound ? "Replaced existing" : "Established",
                rid.to_network_address(true),
                !relcon.inbound           ? "no current"
                    : relcon.inbound_wins ? "have more-preferred"
                                          : "have redundant");
        }
        else
        {
            // we are the client; this container holds our client connections (to relays)
            auto& cc = client_conns[rid];
            bool replaced{cc};
            if (replaced)
            {
                log::error(
                    logcat, "Internal error: duplicate outbound connection established, but that shouldn't happen");
                cc->close();
            }
            cc = std::move(pit->second);
            log::debug(
                logcat,
                "{} connection to {}",
                replaced ? "Replaced existing" : "Established",
                rid.to_network_address(true));
        }

        pending_outbound.erase(pit);

        if (not router.is_service_node)
            router.on_edge_conn_change();
    }

    void Endpoint::on_conn_established(quic::Connection& conn)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        std::shared_ptr<quic::BTRequestStream> inbound_cstream;
        if (conn.is_inbound())
        {
            // We have to set up the control stream here, before the router loop transfer below,
            // because the stream must be queued before stream data gets processed (which could
            // happen immediately after this method call returns) so that we don't accidentally end
            // up with a plain Stream for the stream id rather than a BTRequestStream.
            inbound_cstream = make_control(conn, as_bspan(conn.remote_key()), conn.selected_alpn());
        }

        router._jq->call([this, weak = conn.weak_from_this(), inbound_cstream = std::move(inbound_cstream)]() mutable {
            auto conn = weak.lock();
            if (not conn)
            {
                log::warning(logcat, "Connection died before connection open callback execution!");
                return;
            }

            if (conn->is_inbound())
                on_inbound_conn(std::move(conn), std::move(inbound_cstream));
            else
                on_outbound_conn(std::move(conn));
        });
    }

    Endpoint::~Endpoint() { *canary = false; }

    void Endpoint::on_conn_closed(quic::Connection& conn, uint64_t ec)
    {
        auto alpn = conn.selected_alpn();
        if (alpn == BOOTSTRAP_ALPN)
        {
            assert(conn.is_inbound());  // Outbound bs conns should not use this callback

            // These are untracked, so don't need to enter the below cleanup code.
            log::debug(logcat, "bootstrap connection closed, ec={}", ec);
            return;
        }

        if (alpn == RELAY_ALPN && conn.remote_key().size() != RouterID::SIZE)
        {
            log::debug(logcat, "Rejected inbound connection (ec={}), nothing to do", ec);
            return;
        }

        std::optional<RouterID> rid;
        if (conn.remote_key().size() == RouterID::SIZE)
            rid.emplace(conn.remote_key().first<RouterID::SIZE>());

        // NB: we must not capture a shared_ptr to conn here, because this lambda could outlive
        // `this`; the canary lets us early-return if that happens, but the Connection destruction
        // relies on `this.loop` to destroy: thus if we capture it we could delay that destruction
        // attempt beyond the end of `this.loop`.  Thus we capture everything we need into the
        // lambda here, while we are still in the network loop.

        router._jq->call([this,
                          alive = canary,
                          conn_refid = conn.reference_id(),
                          alpn,
                          rid = std::move(rid),
                          remote_addr = conn.remote(),
                          ec,
                          was_inbound = conn.is_inbound()] {
            if (!*alive)
                return;

            bool found = false;

            if (alpn == RELAY_ALPN)
            {
                assert(router.is_service_node);
                assert(rid);
                if (auto it = relay_conns.find(*rid); it != relay_conns.end())
                {
                    assert(router.is_service_node);
                    auto& relcon = it->second;
                    if (relcon.inbound && relcon.inbound->conn && relcon.inbound->conn->reference_id() == conn_refid)
                    {
                        relcon.close(true);
                        found = true;
                        log::debug(
                            logcat, "Inbound connection from {} closed (ec={})", rid->to_network_address(true), ec);
                    }
                    if (relcon.outbound && relcon.outbound->conn && relcon.outbound->conn->reference_id() == conn_refid)
                    {
                        relcon.close(false);
                        found = true;
                        log::debug(
                            logcat, "Outbound connection to {} closed (ec={})", rid->to_network_address(true), ec);
                    }
                    if (!relcon.conn)
                    {
                        log::debug(logcat, "No remaining relay connection with {}!", rid->to_network_address(true));
                        relay_conns.erase(it);
                    }
                    if (found)
                    {
                        relay_bidir.erase(*rid);
                        return;
                    }
                }

                if (auto it = pending_outbound.find(*rid); it != pending_outbound.end())
                {
                    log::debug(
                        logcat,
                        "Pending relay connection to {} closed before establishing (ec={})",
                        rid->to_network_address(true),
                        ec);
                    pending_outbound.erase(it);
                    found = true;
                }

                if (!found && ec == CONN_CLOSE_REDUNDANT)
                {
                    log::debug(
                        logcat,
                        "Closed redundant connection {} {} @ {} (cid={})",
                        was_inbound ? "from" : "to",
                        rid->to_network_address(true),
                        remote_addr,
                        conn_refid);
                    found = true;
                }
            }
            else if (alpn == CLIENT_ALPN)
            {
                if (router.is_service_node)
                {
                    assert(was_inbound);  // Relays do make outbound client conns for testing,
                                          // but they do not use this close callback.
                    if (auto it = inbound_clients.find(conn_refid); it != inbound_clients.end())
                    {
                        log::debug(logcat, "Client connection from {} closed (ec={})", remote_addr, ec);
                        it->second->close();
                        inbound_clients.erase(it);
                        found = true;
                    }
                }
                else
                {
                    assert(!was_inbound);

                    if (auto it = client_conns.find(*rid); it != client_conns.end() && it->second && it->second->conn
                        && it->second->conn->reference_id() == conn_refid)
                    {
                        log::debug(
                            logcat,
                            "Closed connection to {} (ec={})",
                            rid->to_network_address(!router.is_service_node),
                            ec);
                        client_conns.erase(it);
                        found = true;
                    }
                }
            }
            else if (!was_inbound)
            {
                // Unknown or empty ALPN -- this is an outbound conn that didn't establish (and thus
                // didn't negotiate the ALPN):
                assert(rid);  // Outbound conns start out with the target pubkey known
                if (auto it = pending_outbound.find(*rid); it != pending_outbound.end() && it->second
                    && it->second->conn && it->second->conn->reference_id() == conn_refid)
                {
                    pending_outbound.erase(it);
                    found = true;
                }
            }
            else
                assert(false);  // Somehow we have an *inbound* conn without an ALPN, but that should
                                // never have been established in the first place.

            if (!found)
                log::warning(
                    logcat,
                    "Closed connection {} {} @ {} (cid={}, ec={})",
                    was_inbound ? "from" : "to",
                    rid ? rid->to_string() : "",
                    remote_addr,
                    conn_refid,
                    ec);

            if (not router.is_service_node)
                router.on_edge_conn_change();
        });
    }

    // Establish a no-creds, no-0rtt, bootstrap or relay-testing (client ALPN) connection.
    static auto testcat = log::Cat("testing");
    std::pair<std::shared_ptr<quic::Connection>, std::shared_ptr<quic::BTRequestStream>> special_connect_impl(
        quic::Endpoint& endpoint, const RelayContact& rc, std::string_view alpn)
    {
        std::pair<std::shared_ptr<quic::Connection>, std::shared_ptr<quic::BTRequestStream>> ret;
        auto& [conn, control] = ret;

        bool bs = alpn == BOOTSTRAP_ALPN;

        log::debug(
            logcat,
            "Initiating new {} connection to {} @ {}",
            alpn,
            rc.router_id().to_network_address(true),
            rc.addr());

        conn = endpoint.connect(
            quic::RemoteAddress{rc.router_id().to_view(), rc.addr()},
            quic::opt::idle_timeout{BOOTSTRAP_IDLE_TIMEOUT},
            quic::opt::outbound_alpn(alpn),
            [bs](quic::Connection& conn) {
                log::debug(
                    bs ? logcat : testcat,
                    "Successfully connected to {} {} @ {}",
                    bs ? "bootstrap" : "testee",
                    RouterID{conn.remote_key().first<32>()}.to_network_address(true),
                    conn.remote());
            },
            [bs](quic::Connection& conn, uint64_t ec) {
                if (ec)
                    log::log(
                        bs ? logcat : testcat,
                        bs ? log::Level::warn : log::Level::debug,
                        "{} while connecting to {} {} @ {}",
                        ec == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT)
                            ? "Connection timeout"
                            : "An error occurred (ec={})"_format(ec),
                        bs ? "bootstrap" : "testee",
                        RouterID{conn.remote_key().first<32>()}.to_network_address(true),
                        conn.remote());
                else
                    log::debug(
                        bs ? logcat : testcat,
                        "Connection to {} {} closed.",
                        bs ? "bootstrap" : "testee",
                        RouterID{conn.remote_key().first<32>()}.to_network_address(true));
            });

        control = conn->open_stream<quic::BTRequestStream>();

        return ret;
    }

    std::pair<std::shared_ptr<quic::Connection>, std::shared_ptr<quic::BTRequestStream>> Endpoint::bootstrap_connect(
        const RelayContact& rc)
    {
        return special_connect_impl(*endpoint, rc, BOOTSTRAP_ALPN);
    }

    std::pair<std::shared_ptr<quic::Connection>, std::shared_ptr<quic::BTRequestStream>>
    Endpoint::testing_client_connect(const RelayContact& rc)
    {
        return special_connect_impl(*endpoint, rc, CLIENT_ALPN);
    }

}  // namespace srouter::link
