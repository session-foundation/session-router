#pragma once

#include "connection.hpp"
#include "contact/relay_contact.hpp"
#include "contact/router_id.hpp"
#include "util/time.hpp"

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/connection_ids.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/loop.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <optional>

namespace srouter
{
    class Router;
}  // namespace srouter

namespace srouter::link
{
    class Manager;

    // How long we wait before closing the less-preferred redundant connection when we have
    // bidirection connections between two routers.  Once both sides have both directions, they
    // mutually determine the "winner" and send all future traffic on the winner connection.  This
    // buffer is to allow any messages or data to be handled that might have been send down the
    // less-preferred connection before both directions were established.
    //
    // We also use this value as a timer interval, so redundant connections can stay alive up to
    // twice this value.
    inline constexpr auto REDUNDANT_LINGER = 20s;

    // How long we leave router connections open to session routers that are no longer on the
    // network (i.e. left gracefully or were deregistered).  We don't kill these connections
    // immediately as they may still be in use by existing clients paths, so we keep them alive for
    // longer than the longest path to allow those clients to naturally migrate to new paths.
    inline constexpr auto DEREGGED_LINGER = 30min;

    static constexpr uint64_t CONN_CLOSE_REDUNDANT = 6;

    // Stores relay-to-relay connections.  In order to not lose stream messages, we temporarily
    // allow simultaneous connections in both directions between a pair of relays, but then
    // after a timeout, both sides choose the same winner and drop the other one.  The timeout
    // ensures that if we race to establish that we don't prematurely close while stream data is
    // still in flight (i.e. before both sides have aligned to the winning connection stream).
    struct relay_conn
    {
        // Constructor: takes an argument that is true if the inbound connection should take
        // precedence over the outbound conn when we have both, which is generally performed by
        // comparing rounter IDs (so as to be consistent on both sides).
        explicit relay_conn(bool inbound_wins) : inbound_wins{inbound_wins} {}

        bool inbound_wins;
        std::shared_ptr<link::Connection> inbound;
        std::shared_ptr<link::Connection> outbound;

        // Pointer to the current preferred connection, or nullptr if there is no current
        // connection:
        link::Connection* conn = nullptr;

        // Sets the appropriate inbound/outbound pointer and, if this is the only or the winning
        // connection, also sets it to `conn`.  If the existing inbound/outbound pointer is
        // already set, it is quietly closed before being replaced.
        void set_conn(std::shared_ptr<link::Connection> c, bool is_inbound);

        // Closes either the inbound or outbound connection and drops it from this instance.  If
        // the other connection still exists then `conn` is updated to point at it, otherwise it
        // is set to nullptr.  Does nothing if the indicated connection is already closed.
        void close(bool direction_inbound, uint64_t errcode = 0);

        // Closes all connections, in both directions (if opened).
        void close_all(uint64_t errcode = 0);

        // Closes the "loser" connection, if this instance has connections in both directions.
        void close_redundant();
    };

    class Endpoint
    {
      public:
        explicit Endpoint(Manager& lm);

        ~Endpoint();

        Manager& manager;
        Router& router;

      private:
        // The network loop object.  This *must* be declared before most of the below as some of the
        // things below have destructors that run in this loop.
        std::unique_ptr<quic::Loop> loop;

        // Stores established relay-to-relay connections; only used by service nodes.
        std::unordered_map<RouterID, relay_conn> relay_conns;

        // Stores keys of relay_conns of any relays with which we have bidirectional connections
        // that will need closing of the less-preferred connection (after a timeout).  The value is
        // when the latest connection was stored (used for allowing a safety margin before closing
        // the redundant one).
        std::unordered_map<RouterID, sys_ms> relay_bidir;

        // Stores not-yet-established outbound connections to relays.  When the connection
        // established, it is removed from here and inserted into `client_conns` (clients) or
        // `relay_conns` (relays).
        std::unordered_map<RouterID, std::shared_ptr<link::Connection>> pending_outbound;

        // Stores any "dead" router IDs (i.e. unlocked or deregged) that we have connections with,
        // along with the timestamp of when we first noticed they were no longer valid.  Once we
        // reach DEREGGED_LINGER, we close the connection.
        std::unordered_map<RouterID, std::chrono::steady_clock::time_point> pending_dead;

        // Stores established client-to-relay connections (i.e. outbound edge connections).  Client
        // only.
        std::unordered_map<RouterID, std::shared_ptr<link::Connection>> client_conns;

        // Stores established inbound client-to-relay connections (i.e. edge connections).  Relay
        // only.
        std::unordered_map<quic::ConnectionID, std::shared_ptr<link::Connection>> inbound_clients;

        std::shared_ptr<quic::Endpoint> endpoint;
        quic::TimerID redundancy_timer;
        quic::TimerID dereg_conn_timer;
        std::shared_ptr<quic::GNUTLSCreds> tls_creds;

        // Canary object that gets set to false during destruction to help short-circuit lambda that
        // could potentially outlive `this`:
        std::shared_ptr<bool> canary = std::make_shared<bool>(true);

      public:
        void start_timers();

        // Returns the connection to the given relay.  If there are established connections in both
        // directions (i.e. when running as a relay), this returns the mutually preferred one.
        // Returns nullptr if there is no established connection with the given relay at all.
        link::Connection* get_relay_conn(const RouterID& relay) const;

        // Drops any redundant connections, i.e. where connections between two relays are
        // established in both directions and sufficient time has passed so ensure that all messages
        // are flowing on the mutually preferred connection.
        void close_redundant(sys_ms now = srouter::time_now_ms());

        // Checks for any existing connections to expired nodes and, after a delay, closes them.
        // (They delay is to give time for clients still using a path through us to the deregged
        // node to build and switch to new paths).  This runs infrequently (once/minute) because
        // leaving the connections around for a little longer doesn't hurt anything.
        void check_deregged_conns();

        // Returns an established client->relay connection, if one exists.  Client only.  Returns
        // nullptr if there is no current established connection to the given relay.
        link::Connection* get_client_conn(const RouterID& rid) const;

        // Returns a set of all relays with established (or pending, if `include_pending`)
        // connections.
        std::unordered_set<RouterID> get_current_relays(bool include_pending = false) const;

        // Returns true if there is an established (or pending, if `include_pending`) connection to
        // the given RouterID.
        bool connected_to_relay(const RouterID& relay, bool include_pending = false) const;

        // Returns 5-element array of relay connection counts.  (All values are 0 if this is called
        // on a client instance):
        // - number of relays with established connections.  Note that this counts each relay only
        //   once, i.e. if there are two bidirectional connections between two relays, it is not
        //   counted here twice.  Note that this also means this can be smaller than the sum of the
        //   next two values.
        // - number of established outbound relay-to-relay connections.
        // - number of inbound relay-to-relay connections.
        // - number of pending outbound connections (i.e. to other relays).
        // - number of incoming connections from clients.
        std::array<int, 5> relay_connection_counts() const;

        // Returns the number of client->relay connections.  The first value is the number of
        // established connections, the second is the number of pending connections.
        std::array<int, 2> client_connection_counts() const;

        // Returns the number of relays we are connected to (for relays: relay-to-relay connections,
        // for clients this is simply the number of connections as all connections are to relays).
        // Does not double count relays (i.e. if connections exist in both directions, for
        // relay-to-relay connections).
        //
        // If `include_pending` is true then pending connections to relays are always included in
        // the count (but, as above, without double-counting relays in case the pending connection
        // would become a parallel connection).
        int num_relay_conns(bool include_pending = false) const;

        // If all current established outbound client-to-relay edge connections share the same
        // distinct IP range (according to the unique-hop-mask config setting) then this returns
        // that range.  If there are multiple ranges (or no established connections, or the unique
        // range setting is disabled) then this returns nullopt.
        //
        // This is used when selecting a random terminus when constructing a new inbound path to
        // avoid selecting a terminus that would be forced to violate the unique range setting
        // because of the lack of distinct available edge connection IP networks.
        //
        // This method is only meaningful for clients; relays always return std::nullopt.
        std::optional<quic::ipv4_net> unique_edge_range() const;

        //        bool establish_connection(
        //            quic::RemoteAddress remote,
        //            RouterID rid,
        //            quic::connection_established_callback on_open = nullptr,
        //            quic::connection_closed_callback on_close = nullptr);

        // If there is no existing or pending connection to the given relay, initiates a new
        // outbound connection to it, otherwise does nothing.  Returns true a with the remote is
        // already established, false if it was initiated by this call or was already pending.
        bool ensure_connection(const RelayContact& rc);

        // Returns a reference to the control stream currently in use to send commands to the given
        // relay.  If no connection exists yet with that relay, a new one is constructed (and so the
        // returned control stream might be on an not-yet-established connection).
        //
        // You often do *not* want to use this directly, because commands invoked it on it have
        // their callbacks fired in the network endpoint event loop rather than the router event
        // loop; instead see control_command for a wrapper that transfers callback execution to the
        // router loop.
        quic::BTRequestStream& control_stream_for(const RelayContact& rc);

        // Sends a command on the control stream with `rc`, initiating a new connection if needed to
        // reach `rc`.  This is almost equivalent to `control_stream_for(rc).command(...)` except
        // that the callback, when it fires, is wrapped and transferred to the router loop rather
        // than executing in the endpoint event loop.
        void send_command(
            const RelayContact& rc,
            std::string endpoint,
            std::vector<std::byte> body,
            std::function<void(quic::message)> response_handler);

        // Same as above, but takes an relay router id and looks it up.  If lookup fails, returns
        // false *without* calling the response handler.  Otherwise the message is sent to the
        // remote and the response (when triggered) fires on the router loop.
        bool send_command(
            const RouterID& rid,
            std::string endpoint,
            std::vector<std::byte> body,
            std::function<void(quic::message)> response_handler);

        // Sends a command to a client (i.e. from an edge) on the control stream for the given
        // incoming client connection ID.  Returns true if the message was queued, false if the
        // connection is not valid.
        bool send_command(
            const quic::ConnectionID& client_cid,
            std::string endpoint,
            std::vector<std::byte> body,
            std::function<void(quic::message)> response_handler);

        // Calls one of the above, based on which thing `target` holds
        bool send_command(
            const std::variant<RouterID, quic::ConnectionID>& target,
            std::string endpoint,
            std::vector<std::byte> body,
            std::function<void(quic::message)> response_handler)
        {
            return std::visit(
                [&](const auto& tgt) {
                    return send_command(tgt, std::move(endpoint), std::move(body), std::move(response_handler));
                },
                target);
        }

        // Send a data message (i.e. datagram) to the given relay, if connected.  Returns true if we
        // were able to queue the datagram for sending, false otherwise (such as when there is no
        // fully established connection to the given relay yet).  Unlike `control_command`, this
        // does not initiate a new connection if there is not already one established.
        bool send_datagram(const RouterID& relay, std::vector<std::byte> data);

        // Sends a data message (i.e. datagram) on the given inbound client quic connection, if
        // still connected.  Returns true if we were able to queue it for sending, false otherwise.
        bool send_datagram(const quic::ConnectionID& client_cid, std::vector<std::byte> data);

        // Calls one of the above, based on which thing `target` holds
        bool send_datagram(const std::variant<RouterID, quic::ConnectionID>& target, std::vector<std::byte> data)
        {
            return std::visit([&](const auto& tgt) { return send_datagram(tgt, std::move(data)); }, target);
        }

        // Calls `func` for every relay connection.  If any relays have dual inbound/outbound
        // connections, this is only called for the preferred direction.
        void for_each_relay_conn(std::function<void(const RouterID&, link::Connection&)> func) const;

        void close_connection(const RouterID& rid);

        // Closes all connections and stops the network event loop
        void shutdown();

        // Makes a new connection to the given relay as a Session Router bootstrap client (i.e. using the
        // special bootstrapping ALPN, even if this node is a relay) *without* using an existing
        // connection or tracking it in existing connections.  This is primarily used when
        // bootstrapping to avoid having the connection get treated as a regular relay connection on
        // either side of the connection.  The connection does not use keep-alive and is expected to
        // be short lived.
        //
        // Returns the connection and the control stream through which a bfetch_rc command can be
        // issued.  (This is the only command supported under the bootstrap ALPN).
        std::pair<std::shared_ptr<quic::Connection>, std::shared_ptr<quic::BTRequestStream>> bootstrap_connect(
            const RelayContact& rc);

        // Makes a new connection to the given relay as a Session Router client (i.e. using the client
        // ALPN, even if this node is a relay) *without* using an existing connection or tracking it
        // in existing connections.  This is primarily used for service node testing to ensure we
        // can establish a new connection and avoid having the connection get treated as a regular
        // relay connection on either side of the connection.  The connection does not use
        // keep-alive and is expected to be short lived.
        //
        // Returns the connection and the control stream through which a ping command can be
        // issued.
        std::pair<std::shared_ptr<quic::Connection>, std::shared_ptr<quic::BTRequestStream>> testing_client_connect(
            const RelayContact& rc);

      private:
        std::shared_ptr<quic::BTRequestStream> make_control(
            quic::Connection& conn, std::span<const std::byte> remote_key, std::string_view alpn);

        void on_inbound_conn(std::shared_ptr<quic::Connection> conn, std::shared_ptr<quic::BTRequestStream> control);
        void on_outbound_conn(std::shared_ptr<quic::Connection> conn);

        void on_conn_established(quic::Connection& conn);

        void on_conn_closed(quic::Connection& conn, uint64_t ec);

        std::pair<bool, quic::BTRequestStream*> ctrl_stream_impl(const RelayContact& rc);
    };

}  // namespace srouter::link
