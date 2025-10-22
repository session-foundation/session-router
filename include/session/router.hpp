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

    /// Metadata returned when establishing a session for a TCP or UDP tunnel.
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

        /// The bound local port.  After establishing a Session Router session, clients connect (TCP) or
        /// send (UDP) to this port (on address 127.0.0.1) to reach the destination through session_router.
        uint16_t local_port;

        /// A suggested maximum MTU for the connection.  If the application supports a configurable
        /// MTU, this value is the recommended value that avoids some additional overhead from
        /// packet splitting, which can slightly reduce latency and jitter.  If the application
        /// doesn't support MTU configuration then this value can simply be ignored and Session Router will
        /// split any "too large" packets into two.
        uint16_t suggested_mtu;
    };

    using snode_path = std::vector<std::pair<std::string, std::string>>;
    using session_path = std::pair<snode_path, std::string>;

    class SessionRouter
    {
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
        // established (and thus Session Router is ready to start building paths).  If Session Router is already
        // established, this will schedule an immediate invocation of the callback.
        //
        // If persist is true then the callback will be stored and called *each* time Session Router enters
        // the connected state (i.e. it will be called again if Session Router loses all connectivity and
        // then regains connections).
        void on_connected(std::function<void()> callback, bool persist = false);

        // Schedules the given callback to be fired when Session Router becomes fully disconnected, i.e.
        // loses all established edge connections.  If persist is true then the callback will be
        // fired *each* time Session Router transitions from connected to disconnected state.  If Session Router
        // is not currently connected then the callback will be scheduled immediately.
        void on_disconnected(std::function<void()> callback, bool persist = false);

        // Establishes a UDP session to the given remote (.loki or .snode) and port.  When the
        // Session Router session to the remote is established, the callback is invoked with the info
        // corresponding to the session and tunnel.  This call can happen instantly (before this
        // function call returns) if a session to the given address is already established, but
        // otherwise the callback will be called at some future point when the callback is
        // established.
        //
        // If a connection cannot be established for whatever reason, the `on_failed` callback is
        // invoked with a string giving a descriptive reason.  Like `on_established`, it is possible
        // for this to fire immediately, such as for an unparseable address or if Session Router can
        // determine immediately that the connection will fail.
        //
        // The callbacks must not block as they are called from Session Router's logic thread (and so any
        // blocking will stall Session Router).
        void establish_udp(
            std::string_view remote_view,
            uint16_t port,
            std::function<void(tunnel_info info)> on_established,
            std::function<void(std::string errmsg)> on_failed);

        // Simple synchronous wrapper around the above: this blocks until either `on_established` or
        // `on_failed` is called then returns the tunnel info (success) or throws the error message
        // (failure).  This is provided for quick-and-dirty implementation code; generally code
        // should prefer the callback-based async version, above.
        tunnel_info establish_udp_blocking(std::string_view remote, uint16_t port);

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
