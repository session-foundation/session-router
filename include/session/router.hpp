#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace srouter
{
    struct Context;
    struct Config;
}  // namespace srouter

namespace oxen::quic
{
    class Loop;
}

namespace session::router
{
    enum class Network
    {
        MAINNET,
        TESTNET
    };

    /// The details of an established TCP or UDP tunnel.  This is plain data describing the tunnel;
    /// what keeps a UDP tunnel open is holding the udp_tunnel claim that carries it.
    struct tunnel_info
    {
        /// The requested remote address.  If an ONS entry was requested, this will be the resolved
        /// "fulladdress.loki" rather than the ONS entry value.
        std::string remote;

        /// The requested remote port.  Packets sent to the `local_port` are delivered to this
        /// remote port, and returning packets from that remote back to the incoming source are
        /// routed back to the client and delivered to the source port that sent the original
        /// packet.  Multiple connections to the same address are possible: each different source
        /// port establishes a separate connection (actual TCP connections for TCP, a remembered
        /// mapping for UDP).
        uint16_t remote_port;

        /// The bound local port.  After establishing a Session Router session, clients connect
        /// (TCP) or send (UDP) to this port (on IPv6 localhost address ::1) to reach the
        /// destination through session_router.
        uint16_t local_port;
    };

    /// Why a tunnel that was requested did not come up.
    enum class tunnel_failure
    {
        /// The session did not establish in time.  The remote may well be reachable; this attempt
        /// did not get there.
        timeout,

        /// The remote is a relay for which the network holds no relay contact, and so cannot be
        /// reached at all until it rejoins.  Attempting it again immediately is pointless, but the
        /// verdict is not permanent: it is re-checked on each attempt.
        unreachable,
    };

    class SessionRouter;

    /// A claim on a Session Router UDP tunnel, obtained from SessionRouter::establish_udp().
    ///
    /// Asking for a remote address and port that is already mapped hands back the same mapping
    /// rather than making a new one, so a mapping can have several claims on it at once.  It stays
    /// up until the last of them is destroyed, which means a caller only has to keep its own claim
    /// for as long as it wants the tunnel: releasing it can never pull the tunnel out from under
    /// someone else.
    ///
    /// An empty claim (default-constructed, moved-from, or reset) refers to no tunnel and releases
    /// nothing; test with `operator bool`.  The tunnel's details are reached through `*` and `->`.
    ///
    /// Destroying the SessionRouter releases every tunnel with it, so a claim outliving its router
    /// is harmless.
    class udp_tunnel
    {
        friend class SessionRouter;

        std::weak_ptr<void> _router_alive;
        SessionRouter* _router{nullptr};
        tunnel_info _info;

        udp_tunnel(SessionRouter& router, std::weak_ptr<void> alive, tunnel_info info);

      public:
        udp_tunnel() = default;
        udp_tunnel(udp_tunnel&& other) noexcept { *this = std::move(other); }
        udp_tunnel& operator=(udp_tunnel&& other) noexcept;
        udp_tunnel(const udp_tunnel&) = delete;
        udp_tunnel& operator=(const udp_tunnel&) = delete;
        ~udp_tunnel();

        /// Releases this claim now rather than at destruction, leaving the object empty.
        void reset();

        explicit operator bool() const { return _router != nullptr; }

        const tunnel_info& operator*() const { return _info; }
        const tunnel_info* operator->() const { return &_info; }
    };

    /// One relay of a path.
    struct path_hop
    {
        /// The relay's network address, i.e. "<pubkey>.snode".
        std::string relay;

        /// The relay's public IPv4 address, in dotted-quad form.
        std::string ip;
    };

    using snode_path = std::vector<path_hop>;

    /// The path a session is currently using, and how it has been performing.
    struct path_info
    {
        /// The relays carrying the path, ordered from the edge (our first hop) to the pivot or
        /// final relay.  Empty if the session has no path at the moment.
        snode_path hops;

        /// When the path expires.  Paths are replaced well before this in normal operation, so
        /// this is an upper bound on the path's life rather than a prediction of when the session
        /// will switch paths.  Epoch if there is no path.
        std::chrono::sys_time<std::chrono::milliseconds> expiry;

        /// Mean round-trip time of the path's pings, measured over the *whole* path: from us to
        /// the far end and back.  There is no per-hop timing available.  Zero until the first
        /// response arrives (i.e. whenever `ping_responses` is 0).
        std::chrono::milliseconds latency{0};

        /// Mean absolute difference between consecutive ping round-trip times.  Needs at least two
        /// responses to mean anything; zero until then.
        std::chrono::microseconds jitter{0};

        /// Pings answered, and pings that timed out, over the life of the path.
        int ping_responses{0};
        int ping_timeouts{0};

        /// Consecutive ping timeouts right now; any response resets this to 0.  The path is
        /// abandoned once this exceeds the configured maximum, so a non-zero value here is the
        /// earliest warning that a path is going bad.
        int ping_recent_timeouts{0};
    };

    /// A session's current path, along with the remote the session is with.
    struct session_path
    {
        path_info path;

        /// The session's remote endpoint ("<pubkey>.sesh" or "<pubkey>.snode").  For a relay
        /// session this is the same as the path's final hop; for a client<->client session it is
        /// the far client, reached via that final hop as a pivot.
        std::string remote;
    };

    class SessionRouter
    {
        friend class udp_tunnel;

        // Lets a udp_tunnel that outlives us know not to touch us on the way out.
        std::shared_ptr<void> _alive{std::make_shared<char>()};

        // Releases one claim on a UDP tunnel; the mapping goes away with the last one.
        void release_udp(const std::string& remote, uint16_t port);

        std::unique_ptr<srouter::Context> context;

        struct path_ctor
        {};
        SessionRouter(path_ctor, const std::filesystem::path& p, std::shared_ptr<oxen::quic::Loop> loop);

      public:
        // Starts an embedded Session Router that loads the given string contents as a config file.
        explicit SessionRouter(std::string config, std::shared_ptr<oxen::quic::Loop> existing_loop = nullptr);

        // Starts an embedded Session Router instance with extra configuration specified in the given
        // config file.  (Templatized to avoid ambiguous implicit conversion from std::string
        // conflicting with the constructor above.)
        template <std::same_as<std::filesystem::path> FSPath>
        explicit SessionRouter(const FSPath& config, std::shared_ptr<oxen::quic::Loop> existing_loop = nullptr)
            : SessionRouter{path_ctor{}, config, std::move(existing_loop)}
        {}

        // Starts an embedded Session Router with default config that runs on the given network with
        // default settings.
        explicit SessionRouter(Network network, std::shared_ptr<oxen::quic::Loop> existing_loop = nullptr);

        // Destructor stops the Session Router instance.  The destructor blocks until shutdown is complete.
        ~SessionRouter();

        // Schedules the given callback to be fired when Session Router edge connections are mostly
        // established (and thus Session Router is ready to start building paths).  If Session
        // Router is already established, this will schedule an immediate invocation of the
        // callback.
        //
        // If the `with_path` argument is true (or omitted) then the callback instead fires with
        // there are edge connections *and* at least one inbound/utility path, which is needed to be
        // able to query the network for things like ONS records and client contacts.  `false`, on
        // the other hand, will fire sooner without requiring a path be completed: it is suitable
        // for signalling when Session Router is sufficient connected to start building sessions to
        // relays.
        //
        // If persist is true then the callback will be stored and called *each* time Session Router enters
        // the connected state (i.e. it will be called again if Session Router loses all connectivity and
        // then regains connections and/or paths).
        void on_connected(std::function<void()> callback, bool with_path = true, bool persist = false);

        // Schedules the given callback to be fired when Session Router becomes fully disconnected,
        // i.e.  loses all established edge connections or its last inbound path.  When `with_path`
        // is given and false, this tracks edge disconnection, which means the instance has lost all
        // connectivity; when omitted or true, the callback is also fired if the last inbound path
        // is lost, signalling that network querying and client sessions cannot currently work, but
        // sessions to relays may still be functional.
        //
        // If `persist` is true then the callback will be fired *each* time Session Router
        // transitions from connected to disconnected state.  If Session Router
        // is not currently connected then the callback will be scheduled immediately.
        void on_disconnected(std::function<void()> callback, bool with_path = true, bool persist = false);

        // Establishes a session to the given remote (pubkey.sesh or pubkey.snode), with an IPv6
        // localhost port mapped to a port on the remote.  A limited number of packets (e.g. to
        // establish a connection) can be sent to the mapped port immediately even before the
        // session establishes: a few packets will be queued and delivered once (and if) the session
        // establishes.
        //
        // (This method does not accept SNS names: you need to call resolve_sns() first for that).
        //
        // Exactly one of three things happens:
        //
        // 1. It throws, if `remote` is unparseable, is an SNS name, or `port` is 0.  Nothing is
        //    mapped and no callback is ever invoked.
        //
        // 2. It returns an empty claim, if `remote` is a relay the network holds no relay contact
        //    for.  We hold contacts for every relay participating in the network, so a relay
        //    without one is not participating (it may be running a version without Session Router,
        //    or be misconfigured).  Nothing is mapped and no callback is ever invoked, so a caller
        //    choosing between several relays can move on to the next immediately rather than
        //    waiting out a build timeout.
        //
        //    This is a statement about right now rather than a permanent one, and it only happens
        //    once relay contacts have actually been fetched: before the first fetch completes the
        //    request is held until we know the answer, so this never guesses.
        //
        // 3. It returns a claim on the mapping, carrying its port information, and exactly one of
        //    the two callbacks is subsequently invoked (whichever of them was provided):
        //
        //    - `on_established(info)`, once the session is up, with the same tunnel_info the claim
        //      carries.  This one *can* fire before establish_udp returns, if a session to the
        //      remote already exists, so be ready for it to run during the call.
        //
        //    - `on_failed(unreachable)`, if the relay turned out to have no relay contact after
        //      all.  This is case 2 discovered late: we had not yet fetched contacts when asked, so
        //      the mapping was made before the answer came back.  Unlike case 2, a mapping does
        //      exist and the claim is real.
        //
        //    - `on_failed(timeout)`, if the session did not come up in time.  Unlike the above, the
        //      remote may well be reachable and worth another attempt shortly.
        //
        //    `on_failed` is never invoked before establish_udp returns.  Neither callback fires if
        //    the SessionRouter is destroyed while the session is still coming up.
        //
        // A failure does not release the tunnel: it stays mapped for as long as a claim is held,
        // and sending to the tunnel port again will attempt to re-establish the session.  Drop the
        // claim if you want it gone.
        //
        // The tunnel stays up until every claim on it has been destroyed (or the SessionRouter is),
        // so a caller need only hold its claim for as long as it wants the tunnel; there is nothing
        // to remember to call.  Asking for an already-mapped remote/port returns another claim on
        // that same mapping rather than creating a new one, so releasing a claim can never take the
        // tunnel away from another holder.
        //
        // Take care not to use very slow or blocking code inside the callbacks: they are called
        // from Session Router's logic thread (and so any blocking will stall Session Router).
        udp_tunnel establish_udp(
            std::string_view remote,
            uint16_t port,
            std::function<void(tunnel_info)> on_established = nullptr,
            std::function<void(tunnel_failure)> on_failed = nullptr);

        // Takes an ONS/SNS address such as "blocks.loki" and attempts to resolve it to a Session
        // Router client (aka hidden service) address such as
        // "kcpyawm9se7trdbzncimdi5t7st4p5mh9i1mg7gkpuubi4k4ku1y.sesh".
        //
        // This method will also accept a full network address (PUBKEY.sesh or PUBKEY.snode), in
        // which case it simply instantly calls the callback with the same address.  (This
        // capability is designed to allow this method to be used with an address that could be
        // either ONS/SNS or direct pubkey).
        //
        // When the name is resolved, the callback will be invoked with the network address.  If the
        // name does not exist or a timeout occurs it will be invoked with nullopt and a second
        // argument that is true if we timed out (i.e. don't know), false if we got a definitive
        // answer from the network that the name does not exist.  (The bool should not be used when
        // `addr` has a value).
        //
        // It is possible for the callback to be called instantly (i.e. before resolve_sns returns)
        // if the result is already cached, or when given a direct pubkey address rather than a
        // resolvable ONS/SNS name.
        //
        // This method will throw an invalid_argument exception if the given address is neither a
        // valid pubkey address nor potentially valid ONS/SNS address.
        void resolve(std::string address, std::function<void(std::optional<std::string> addr, bool timeout)> callback);

        // If we have a session with the given remote, returns the path we are currently using for
        // that session, along with its statistics.  In the case of a client<->client session, the
        // final hop will be the relay which we are using as a pivot.
        //
        // If there is a session but no current path, the returned path_info has no hops and
        // zeroed statistics.
        // If there is not a session to the remote, std::nullopt is returned.
        std::optional<path_info> get_path_for_session(std::string_view remote);

        // Returns the path we're currently using for each session along with the remote endpoint
        // of that session.  In the case of snode (relay) sessions, the remote endpoint will be
        // the same as the path terminus.  In the case of client<->client sessions, the remote
        // endpoint is the client which we're connected to via that path as a relay.
        std::vector<session_path> get_all_session_paths();
    };

    template SessionRouter::SessionRouter(const std::filesystem::path&, std::shared_ptr<oxen::quic::Loop>);

}  // namespace session::router
