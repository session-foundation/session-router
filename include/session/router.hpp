#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <thread>
#include <type_traits>

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

        /// A suggested maximum payload size for the tunnel.  If the application supports a
        /// configurable payload size, using this value avoids additional overhead from packet
        /// splitting, which can slightly reduce latency and jitter.  nullopt means the outer
        /// connection's MTU is unknown (PMTUD without a cap); the application should use its
        /// own default.  If the application doesn't support payload size configuration then
        /// this value can simply be ignored and Session Router will split any "too large"
        /// packets into two.
        std::optional<uint16_t> suggested_mtu;
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

        /// The remote advertises that it cannot accept tunnelled TCP connections, which only a
        /// client running a full tun interface can do.  (TCP only.)  The session itself is fine; it
        /// is TCP that will never work with this remote, so retrying is pointless until the remote
        /// itself changes.
        no_tcp,
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

    /// A claim on a Session Router TCP tunnel, obtained from SessionRouter::establish_tcp().
    ///
    /// This behaves exactly as udp_tunnel does, and the notes there about sharing, releasing, and
    /// outliving the SessionRouter apply here too: the mapping stays up until the last claim on it
    /// is destroyed.
    ///
    /// Releasing the last claim closes the local listening port *and* the TCP connections already
    /// established through it: holding a claim is what keeps the tunnel alive, so nothing outlives
    /// the last one.  Keep the claim for as long as you want the connections.
    class tcp_tunnel
    {
        friend class SessionRouter;

        std::weak_ptr<void> _router_alive;
        SessionRouter* _router{nullptr};
        tunnel_info _info;

        tcp_tunnel(SessionRouter& router, std::weak_ptr<void> alive, tunnel_info info);

      public:
        tcp_tunnel() = default;
        tcp_tunnel(tcp_tunnel&& other) noexcept { *this = std::move(other); }
        tcp_tunnel& operator=(tcp_tunnel&& other) noexcept;
        tcp_tunnel(const tcp_tunnel&) = delete;
        tcp_tunnel& operator=(const tcp_tunnel&) = delete;
        ~tcp_tunnel();

        /// Releases this claim now rather than at destruction, leaving the object empty.
        void reset();

        explicit operator bool() const { return _router != nullptr; }

        const tunnel_info& operator*() const { return _info; }
        const tunnel_info* operator->() const { return &_info; }
    };

    using snode_path = std::vector<std::pair<std::string, std::string>>;
    using session_path = std::pair<snode_path, std::string>;

    class SessionRouter
    {
        friend class udp_tunnel;
        friend class tcp_tunnel;

        // Lets a udp_tunnel/tcp_tunnel that outlives us know not to touch us on the way out.
        std::shared_ptr<void> _alive{std::make_shared<char>()};

        // Releases one claim on a UDP tunnel; the mapping goes away with the last one.
        void release_udp(const std::string& remote, uint16_t port);

        // Releases one claim on a TCP tunnel; the mapping goes away with the last one.
        void release_tcp(const std::string& remote, uint16_t port);

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

        // The TCP counterpart of establish_udp: establishes a session to the given remote and maps
        // an IPv6 localhost port that the application connects to with ordinary TCP.  Each
        // connection made to that port becomes a separate connection to `port` on the remote, so a
        // single mapping carries as many concurrent connections as the application opens.
        //
        // (As with establish_udp, this does not accept SNS names: call resolve() first.)
        //
        // The outcomes are the same three as establish_udp, with two differences:
        //
        // - It also returns an empty claim (mapping nothing, no callback) if the remote's client
        //   contact says it does not accept tunnelled TCP connections.  Only clients running a full
        //   tun interface can terminate them, so an embedded client cannot be a destination.
        //
        // - `on_failed(no_tcp)` is invoked if that only becomes apparent later, i.e. we had no
        //   client contact for the remote when the port was mapped and it turned out, once we did,
        //   not to accept them.  As with `unreachable`, the mapping exists and the claim is real.
        //
        // Unlike UDP, nothing can be sent before the session is established: a TCP connection made
        // to the mapped port before then is held until the session comes up, and dropped if it does
        // not.
        //
        // `tunnel_info::suggested_mtu` is always nullopt for TCP: segment sizes are not the
        // application's to choose.
        //
        // Take care not to use very slow or blocking code inside the callbacks: they are called from
        // Session Router's logic thread (and so any blocking will stall Session Router).
        tcp_tunnel establish_tcp(
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
        // that session.  In the case of a client<->client session, this will be the relay which we
        // are using as a pivot.
        //
        // If there is a session but no current path, an empty vector is
        // returned.
        // If there is not a session to the remote, std::nullopt is returned.
        std::optional<snode_path> get_path_for_session(std::string_view remote);

        // Returns the path we're currently using for each session along with the remote endpoint
        // of that session.  In the case of snode (relay) sessions, the remote endpoint will be
        // the same as the path terminus.  In the case of client<->client sessions, the remote
        // endpoint is the client which we're connected to via that path as a relay.
        std::vector<session_path> get_all_session_paths();
    };

    template SessionRouter::SessionRouter(const std::filesystem::path&, std::shared_ptr<oxen::quic::Loop>);

}  // namespace session::router
