#pragma once

#include "config/definition.hpp"
#include "consensus/reachability.hpp"
#include "contact/relay_contact.hpp"
#include "crypto/key_manager.hpp"
#include "handlers/session.hpp"
#include "handlers/tun.hpp"
#include "path/build_stats.hpp"
#include "path/path_context.hpp"
#include "profiling.hpp"
#include "route_poker.hpp"
#include "router/rpc_backend.hpp"
#include "rpc/oxend_client.hpp"
#include "util/str.hpp"
#include "util/time.hpp"
#include "vpn/platform.hpp"

#include <oxen/quic/loop.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <type_traits>

namespace oxenmq
{
    class OxenMQ;
}

namespace srouter
{

    namespace dns
    {
        class Listener;
    }
    namespace link
    {
        struct Connection;
        class Endpoint;
        class Manager;
    }  // namespace link

    namespace rpc
    {
        class RPCServer;
        class OxendRPC;
    }  // namespace rpc

    namespace consensus
    {
        class reachability_testing;
    }  // namespace consensus

    namespace quic = oxen::quic;

    inline constexpr std::chrono::milliseconds ROUTER_TICK_INTERVAL{250ms};

    inline constexpr std::chrono::milliseconds RC_UPDATE_INTERVAL{10min};

    // Upon startup, relays will attempt to connect to this many nodes per second (divided into the
    // number of ticks per second) to try to reach full mesh as quickly as possible.  Note that a
    // single node restarting will full mesh almost instantly regardless of this setting (because
    // all other nodes will want to re-connect to it), and so this mainly affects how quickly the
    // network reestablishes after a significant number of nodes restart or regain connectivity all
    // at once.
    inline constexpr int RELAY_CONNECTS_PER_TICK{10};

    // DISCUSS: ask tom and jason about this
    // how big of a time skip before we reset network state
    inline constexpr std::chrono::milliseconds NETWORK_RESET_SKIP_INTERVAL{1min};

    inline constexpr std::chrono::milliseconds REPORT_STATS_INTERVAL{1min};
    inline constexpr std::chrono::milliseconds REPORT_STATS_INTERVAL_DEBUG{10s};

    inline constexpr std::chrono::milliseconds DECOMM_WARNING_INTERVAL{5min};

    inline constexpr auto SERVICE_MANAGER_REPORT_INTERVAL{5s};

    // The proportion of its target number of edge connections a client needs to have established
    // connections with before we consider it "connected" to the network.  We allow less than full
    // connectivity so that a single relay connection timeout doesn't stall connectivity for the
    // full timeout duration, but generally want more than 1 so that we don't end up clustering all
    // initial path builds through a single edge.
    using CLIENT_CONNECTED_THRESHOLD = std::ratio<2, 3>;

    class ContactDB;
    class NodeDB;

    class Router
    {
      public:
        // Starts Session Router immediately upon construction.
        explicit Router(
            Config conf,
            std::shared_ptr<quic::Loop> loop,
            std::shared_ptr<vpn::Platform> vpnPlatform,
            std::promise<void> close_promise);

        ~Router();

        // Non-copyable/movable:
        Router(const Router&) = delete;
        Router(Router&&) = delete;
        Router& operator=(const Router&) = delete;
        Router& operator=(Router&&) = delete;

      private:
        // Internal functions called during construction:
        void configure();
        void start();

        Config _config;

      public:
        const std::shared_ptr<quic::Loop> _loop;

        // unique_ptr instead of concrete instance so methods which are const apart from using
        // this object can still be const.
        // FIXME: make sure this is okay?
        const std::unique_ptr<quic::JobQueue> _jq;

      private:
        // path to write our self signed rc to
        std::filesystem::path our_rc_file;

        std::shared_ptr<oxenmq::OxenMQ> _omq{};

        std::atomic<bool> _is_stopping{false};
        std::atomic<bool> _is_running{false};

        // True once we have enough edges
        bool _is_edge_connected{false};
        // True once we have at least one inbound/utility path.  Note that this is subtly different
        // than the `is_path_connected()` method and the on_connected triggers: this only tracks
        // whether we have paths, but the public path connectivity checks also require edge
        // connections.
        bool _has_established_paths{false};

        // Held via the core IReachability interface; the concrete (relay-only) implementation is
        // constructed by the full seam and is null in embedded/core-only builds.
        std::shared_ptr<consensus::IReachability> _router_testing;

        // The actual network address we use for communications:
        quic::Address _listen_address;

        // The advertised public IP address for relays.  This is often the same as _listen_address,
        // but can be different in exotic setups (e.g. where a known public IP is forwarded to an
        // internal IP).  Always set for a relay.
        std::optional<quic::Address> _public_address;

        std::unique_ptr<handlers::SessionEndpoint> _session_endpoint;

        std::unique_ptr<link::Manager> _link_manager;
        link::Endpoint* _link_endpoint = nullptr;

        // These are only created in full platform mode (not embedded clients)
        std::shared_ptr<handlers::ITunnel> _tun;
        std::shared_ptr<dns::Listener> _dns;
        std::shared_ptr<vpn::Platform> _vpn;
        std::shared_ptr<RoutePoker> _route_poker;

        std::promise<void> _close_promise;

      public:
        // Tiny event loop + thread for handling disk I/O jobs without affecting other loops.  (It
        // is up here because it must destroy after _node_db, which uses it.)
        quic::Loop disk_loop;

        // Job queue for disk_loop, for the same reason as _jq: ~Router stops it before any member
        // is destroyed, which cancels the disk timers registered on it.  Declared after disk_loop
        // so that it dies first.
        quic::JobQueue disk_jq{disk_loop};

      private:
        std::unique_ptr<ContactDB> _contact_db;
        std::unique_ptr<NodeDB> _node_db;

        quic::TimerID _tick_timer;

        // Might not be set/used, depending on the platform:
        quic::TimerID _service_stat_timer;

        quic::TimerID _gossip_timer;

        steady_ms _last_stats_report{};
        steady_ms _next_dereg_warning{steady_now_ms() + 15s};

        // Application callback(s) to fire as soon as we reach "connected" or "disconnected" status,
        // with different versions for "edge connected" or "path connected".
        //
        // Typically used as a "ready-to-go" callback during initialization.  The bool is whether
        // the callback is persistent (true) or one-time (false).  Note that callbacks are only
        // called when the connected state changes: that is when we were disconnected and became
        // connected, or were connected and became disconnected.
        std::list<std::pair<std::function<void()>, bool>> _on_edge_connected, _on_edge_disconnected, _on_path_connected,
            _on_path_disconnected;

        // These aren't actually shared, but we unique_ptr requires destructor visibility, which
        // embedded-only clients won't have as they don't compile any RPC code.
        std::shared_ptr<rpc::RPCServer> _rpc_server;
        std::shared_ptr<rpc::IOxendClient> _oxend;

        Profiling _router_profiling;

        bool should_report_stats(steady_ms now) const;

        std::string _stats_line(sys_ms now) const;

        void report_stats();

        bool insufficient_peers() const;

        void init_logging();

        void process_config();

        void _relay_tick(sys_ms now);

        void _client_tick(sys_ms now);

        void tick();

        void start_timers();

      public:
        path::PathContext path_context{*this};
        path::BuildStats path_builds{};
        KeyManager key_manager;

        const bool is_service_node{_config.router.is_relay};

        bool is_fully_meshed() const;

        const std::shared_ptr<handlers::ITunnel>& tun_endpoint() { return _tun; }

        // Looks up the given IP in our TUN mapping and, if it is a TUN address and maps to a remote, returns the
        // network address of the mapped-to address.  The `.second` part of the result indicates
        // whether the IP is on our TUN range, even if it is unmapped.  That is, it can return:
        // {address, true} -- address in tun range, and mapped
        // {nullopt, true} -- address in tun range, but not mapped to a remote
        // {nullopt, false} -- address not in tun range (or no tun at all)
        std::pair<std::optional<NetworkAddress>, bool> reverse_lookup(const ipv4& addr) const;
        std::pair<std::optional<NetworkAddress>, bool> reverse_lookup(const ipv6& addr) const;

        // Returns the net Platform pointer, or nullptr if this is an embedded client.
        const srouter::net::Platform* net() const;

        const std::shared_ptr<vpn::Platform>& vpn_platform() const { return _vpn; }

        handlers::SessionEndpoint& session_endpoint() { return *_session_endpoint; }
        const handlers::SessionEndpoint& session_endpoint() const { return *_session_endpoint; }

        link::Manager& link_manager() { return *_link_manager; }
        const link::Manager& link_manager() const { return *_link_manager; }
        link::Endpoint& link_endpoint()
        {
            assert(_link_endpoint);
            return *_link_endpoint;
        }
        const link::Endpoint& link_endpoint() const
        {
            assert(_link_endpoint);
            return *_link_endpoint;
        }

        const Config& config() const { return _config; }

        ContactDB& contact_db()
        {
            assert(_contact_db);
            return *_contact_db;
        }
        const ContactDB& contact_db() const
        {
            assert(_contact_db);
            return *_contact_db;
        }

        NodeDB& node_db()
        {
            assert(_node_db);
            return *_node_db;
        }
        const NodeDB& node_db() const
        {
            assert(_node_db);
            return *_node_db;
        }

        NetID netid() const { return _config.router.net_id; }

        bool embedded() const { return _config.type == config::Type::EmbeddedClient; }

        rpc::IOxendClient* oxend() const { return _oxend.get(); }

        const Ed25519SecretKey& secret_key() const { return key_manager.secret_key; }
        const RouterID& id() const { return key_manager.router_id(); }

        Profiling& router_profiling() { return _router_profiling; }

        quic::Loop& loop() { return *_loop; }

        // If this router is not a registered service node, does nothing.  Otherwise this regenerate
        // the RC for this router, add it to the nodedb, saves it to disk, and gossips it.
        void regenerate_rc();

        const quic::Address& listen_addr() const { return _listen_address; }

        // Returns the relay's advertised public address.  MUST NOT BE CALLED ON A CLIENT INSTANCE!
        const quic::Address& public_addr() const
        {
            assert(_public_address);
            return *_public_address;
        }

        /// return true if we a registered service node (either active or decommissioned).
        bool appears_registered() const;

        steady_ms _last_tick;

        std::function<void(void)> _router_close_cb;

        void set_router_close_cb(std::function<void(void)> hook) { _router_close_cb = hook; }

        bool looks_alive() const { return steady_now_ms() - _last_tick <= 30s; }

        // RoutePoker& route_poker() { return *_route_poker; }
        // const RoutePoker& route_poker() const { return *_route_poker; }

        std::string status_line();

        // Returns the client "edge connectivity" status: we enter "edge connected" state once the
        // target number of edge router connections is reached, and we lose connected state when we
        // lose all edge connections.  Application code can monitor this state by setting callbacks
        // via `on_connected`/`on_disconnected`.
        bool is_edge_connected() const;

        // Returns the client "path connectivity" status: this requires edge connectivity (see
        // above) but also requires that the router has at least one established inbound/utility
        // path, as is required for things like SNS queries and client contact retrieval and
        // publishing.
        bool is_path_connected() const;

        //
        // If `with_paths` is false, this returns true if we have enough edge connections, which is
        // enough to be able to build outbound sessions to routers.  If true, the returns true if we
        // have edge connections *and* at least one inbound/utility path, which is needed for things
        // like client contact lookups and ONS queries.

        // Adds an application callback to invoke when the connectivity state changes to "connected"
        // (see is_connected).  If the state is already connected when this is called, the callback
        // will be invoked immediately.  If `persistent` is true then the callback will be stored
        // and called again if the state leaves and re-enters the connected state.
        void on_connected(std::function<void()> callback, bool with_paths, bool persistent);

        // Like `is_connected`, but fires on disconnections.
        void on_disconnected(std::function<void()> callback, bool with_paths, bool persistent);

        // Internal method: called from link::Endpoint to re-check and possibly change connected
        // state when a client edge connection is established or lost.
        void on_edge_conn_change();

        // Internal method: called from SessionEndpoint when we establish (true) an inbound/utility
        // path and previously had none; or when we lose our last inbound/utility path (false).
        void on_inbound_path_change(bool connected);

        // Called when we get a relay testing ping to pass through to the router tester so that it
        // can warn if we haven't received pings in a long time.
        void on_test_ping();

        bool is_running() const { return _is_running; }

        bool is_stopping() const { return _is_stopping; }

        bool is_exit_node() const;

        std::optional<std::string> OxendErrorState() const;

        void close();

        /// stop running the router logic gracefully
        void stop();

        void fetch_snode_keys();

        void teardown();
    };
}  // namespace srouter
