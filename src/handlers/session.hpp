#pragma once

#include "address/address.hpp"
#include "config/config.hpp"
#include "contact/client_contact.hpp"
#include "ev/tcp.hpp"
#include "path/path_handler.hpp"
#include "path/transit_hop.hpp"
#include "session/session.hpp"
#include "util/random.hpp"
#include "util/time.hpp"

#include <chrono>
#include <concepts>
#include <memory>

namespace srouter
{
    namespace rpc
    {
        class RPCServer;
    }

    namespace handlers
    {
        using session::session_tag;

        class SessionEndpoint final : public path::PathHandler
        {
            friend class rpc::RPCServer;
            friend class session::Session;

            // Inbound path lifetimes within a slot are always determined relative to this base
            // value, so that if we need a path in the (15,20] minute range, we will always pick the
            // same value in that slot by using this basis value.
            const std::chrono::sys_seconds path_expiry_basis =
                std::chrono::floor<std::chrono::seconds>(srouter::time_now_ms());

            std::unordered_map<NetworkAddress, std::shared_ptr<session::Session>> _sessions;
            std::unordered_map<session_tag, std::shared_ptr<session::Session>> _session_tags;

            session_tag last_tag = static_cast<session_tag>(srouter::csrng());

            // this could probably map to a pair of vectors, or pending packets could
            // be wrapped in callbacks, but for now this works
            // std::unordered_map<NetworkAddress, std::vector<IPPacket>> pending_sessions;
            // std::unordered_map<NetworkAddress, std::vector<std::function<void(bool)>>> pending_session_hooks;

            std::optional<ClientContact> client_contact;
            std::optional<Ed25519BlindedKey> cc_blind_keys;
            int cc_count = -1;

            // Used for logging connected/disconnected status:
            bool connected = false;

            // auth tokens for making outbound sessions; some of these are copied at construction,
            // some (with ONS names) get looked up and populated later.
            std::unordered_map<NetworkAddress, std::string> _auth_tokens;

            std::optional<std::string_view> fetch_auth_token(const NetworkAddress& remote) const;

            void close_session(const std::shared_ptr<session::Session>& s, bool send_close);

            void on_path_build_failure(int64_t build_id, path::Path* path, bool timeout) override;
            void on_path_build_success(int64_t build_id, path::Path& p) override;
            void no_established_paths_left() override;

            void session_post_init(std::shared_ptr<session::InboundSession> new_session);

            // Returns a random amount of path "fuzz" to add to the path build time to make it
            // harder to correlate repeated path builds over time from the same client.
            //
            // The value is cached so that repeated calls with the same slot return the same value.
            //
            // This currently returns a truncated normal distribution with truncation points at 0
            // and MAX_LIFETIME_FUZZ such that the truncation point eliminates values above the
            // 0.5th percentile of the distribution.
            std::chrono::seconds inbound_path_fuzz(int slot);

            // The cache of slot fuzz values returned by inbound_path_fuzz.
            std::map<int, std::chrono::seconds> _slot_fuzz;

            // Called to clean up expired slot values out of _slot_fuzz
            void cleanup_old_fuzz(int oldest_slot);

            struct mapped_remote
            {
                NetworkAddress remote;
                uint16_t port;

                bool operator==(const mapped_remote&) const = default;

                struct hash
                {
                    size_t operator()(const mapped_remote& m) const noexcept
                    {
                        auto h = std::hash<NetworkAddress>{}(m.remote);
                        h ^= std::hash<uint16_t>{}(m.port) + oxen::quic::inverse_golden_ratio + (h << 6) + (h >> 2);
                        return h;
                    }
                };
            };
            // UDP port bidirectional map, obfuscating the randomized source port from the user and
            // mapping that obfuscated port back to that obfuscated port for return traffic.  This
            // is both to track used ports so we don't accept traffic to an unmapped one, as well as
            // in case port selection is fingerprintable.
            //
            // _udp_client_ports maps local application source port -> pseudo source port
            // _udp_return_ports maps pseudo dest port -> {local socket, application dest port}
            //
            // How this all works is:
            // - client app maps REMOTE:1234, we start building a session to REMOTE, start a UDP
            //   listener on a random localhost port (say :5678), where that listener knows to
            //   forward received UDP packets to REMOTE:1234, returning that random localhost port
            //   back to the client to start using.
            // - application sends UDP packets to localhost:5678 from source :22334
            //   - if this is the first time we've seen that source port in the mapped UDP socket,
            //     we pick a fake mapping port, say 13579, add a new mapped pair for it:
            //
            //         {{REMOTE:22334} -> 13579}  # added to _udp_client_ports
            //         {{REMOTE:13579} -> 22334}  # added to _udp_return_ports
            //
            //   - we use the pre-existing or newly inserted _u_c_p mapped pair to rewrite the
            //     src/dest in the UDP packet to src=[::]:13579, dest=[::]:1234
            // - remote sends UDP packet back from :1234 -- we see a return packet with dest
            //   [::]:13579, look that up in _u_r_p, get the app port :22334 out of that, and use
            //   the source port 1234 to get the socket out of _udp_handles, and then use both of
            //   those to send the datagram to the application at [::1]:22334.
            std::unordered_map<mapped_remote, uint16_t, mapped_remote::hash> _udp_client_ports;
            std::unordered_map<mapped_remote, uint16_t, mapped_remote::hash> _udp_return_ports;

            struct udp_handle
            {
                std::unique_ptr<quic::UDPSocket> socket;

                // Keys of _udp_client_ports belonging to this handle, used when deleting it.
                std::vector<mapped_remote> cports;

                // How many callers currently hold this mapping.  Asking for a remote:port that is
                // already mapped hands back the same socket rather than a new one, so the mapping
                // outlives any single holder: it is torn down when the last one unmaps it, not the
                // first.
                int holders = 0;
            };

            // Stores any established embedded client UDP maps: {remote:port} -> handle, so that you
            // can safely ask for the same remote:port again and just get the existing one rather
            // than a new listening socket.
            std::unordered_map<mapped_remote, udp_handle, mapped_remote::hash> _udp_handles;

            struct tcp_handle
            {
                std::shared_ptr<TCPHandle> listener;

                // How many callers currently hold this mapping, exactly as for udp_handle: the
                // mapping is torn down by the last holder to release it, not the first.
                int holders = 0;
            };

            // Established embedded client TCP maps: {remote:port} -> listener.  The listener lives
            // here rather than on the session because it has to outlive session churn: the tunnel
            // beneath it can come and go (a dead path, an idle teardown, a session timing out)
            // without the port the application was handed changing underneath it.
            std::unordered_map<mapped_remote, tcp_handle, mapped_remote::hash> _tcp_handles;

            // Pairs a newly accepted connection on a mapped local TCP port with a stream to the
            // remote, obtaining (or re-establishing) the session as needed.  Returns nullptr if it
            // cannot be tunnelled, in which case the local connection is dropped.
            TCPConnection* tunnel_tcp_connection(const mapped_remote& target, bufferevent* bev, TCPConnection::fd_t fd);

            uint16_t _next_udp_client_port{0};

            template <typename K, typename V>
            using lookup_cache = std::unordered_map<K, std::pair<std::optional<V>, sys_ms>>;

            // onsname.loki -> {address, expiry}.  The address can be nullopt if we received an
            // affirmative "not registered" response (but the entry will not be added if we failed
            // to get or parse the response).
            lookup_cache<std::string, NetworkAddress> _sns_cache;
            static constexpr auto SNS_CACHE_TIME = 5min;

            // Client -> ClientContact+expiry for CCs we have looked up recently.  For CCs where
            // lookup fails, we insert a nullopt with an expiry that is a few seconds from now;
            // otherwise we set the expiry to ClientContact record's expiry.
            lookup_cache<RouterID, ClientContact> _cc_cache;
            static constexpr auto NO_CC_CACHE_TIME = 15s;

          public:
            SessionEndpoint(Router& r);

            void stop(bool send_close);

            // Checks if we need more inbound paths and, if so, starts building them.
            void update_paths(sys_ms now) override;

            // bool build_path_to_random(bool exclude_current_termini)

            /// Returns array of:
            /// - inbound sessions (i.e. from remote clients)
            /// - outbound relay sessions (pending or established)
            /// - outbound client sessions (pending or established)
            /// - pending outbound relay sessions
            /// - pending outbound client sessions
            ///
            /// For relays, all but the first value will be 0 (relays do not establish outbound
            /// sessions).
            std::array<int, 5> session_stats() const;

            /// Returns array of path counts:
            /// - inbound/utility paths (used for inbound sessions and network queries)
            /// - paths for outbound relay sessions
            /// - paths for outbound client sessions
            std::array<int, 3> path_stats(sys_ms now = srouter::time_now_ms()) const;

            // quic::Address local_address() const { return _local_addr; }

            template <std::derived_from<session::Session> S = session::Session>
            S* get_session(const session_tag& tag) const
            {
                if (tag == 0)  // Reserved "not a tag" value
                    return nullptr;
                auto it = _session_tags.find(tag);
                if (it == _session_tags.end())
                    return nullptr;
                return dynamic_cast<S*>(it->second.get());
            }

            template <std::derived_from<session::Session> S = session::Session>
            S* get_session(const NetworkAddress& remote) const
            {
                auto it = _sessions.find(remote);
                if (it == _sessions.end())
                    return nullptr;
                return dynamic_cast<S*>(it->second.get());
            }

            template <std::derived_from<session::Session> S = session::Session>
            S* get_session_shared(const NetworkAddress& remote) const
            {
                auto it = _sessions.find(remote);
                if (it == _sessions.end())
                    return nullptr;
                if constexpr (std::same_as<S, session::Session>)
                    return it->second;
                else
                    return dynamic_pointer_cast<S>(it->second);
            }

            bool close_session(NetworkAddress remote, bool send_close = false);

            bool close_session(session_tag t, bool send_close = false);

            /// Called to perform CC publishing.  This is called upon inbound path build completion
            /// if that completion results in a full set of target paths, so that we effectively
            /// republish whenever inbound paths change.
            void update_and_publish_localcc();

            void publish_client_contact(std::string_view encrypted_cc);

            /// Accesses the current client contact, if we are a client, otherwise returns nullptr.
            const ClientContact* maybe_cc() const { return client_contact ? &*client_contact : nullptr; }
            /// Asserts that we are a client and references a reference to the CC
            const ClientContact& cc() const
            {
                assert(client_contact);
                return *client_contact;
            }

            // Updates a CC cache entry if the given value is better than the one already in the
            // cache.  Returns a reference to the cache entry (which *could* be a copy of the input,
            // but also could be a previous existing entry if the existing cache value is
            // preferrable).
            const std::optional<ClientContact>& update_cc(const RouterID& remote, std::optional<ClientContact>&& cc);

            // SessionEndpoint can use either a whitelist or a static auth token list to validate
            // incoming requests to initiate a session
            bool validate(const NetworkAddress& remote, std::optional<std::string> maybe_auth = std::nullopt);

            std::optional<ipv4> map_session_v4(const session::Session& s);
            std::optional<ipv6> map_session_v6(const session::Session& s);

            void handle_session_init(std::span<const std::byte> payload, std::shared_ptr<path::Path> path);
            void handle_session_init(std::span<const std::byte> payload, std::shared_ptr<path::TransitHop> thop);

            // Called on a client when we receive a session_init from another client to create an
            // InboundClientSession.  Returns nullopt if the session cannot be created, otherwise
            // returns the random session tag we have associated with the inbound session.
            std::optional<session_tag> create_inbound_session(
                const NetworkAddress& initiator,
                const HopID& remote_pivot_txid,
                std::shared_ptr<path::Path> path,
                const SymmKey& session_key);

            // Called on a relay when we receive a session_init from a client to create an
            // InboundRelaySession.  Returns nullopt if the session cannot be created, otherwise
            // returns the random session tag we have associated with the inbound session.
            std::optional<session_tag> create_inbound_session(
                const NetworkAddress& initiator,
                const HopID& remote_pivot_txid,
                std::shared_ptr<path::TransitHop> path,
                const SymmKey& session_key);

            // lookup SNS address to return "{pubkey}.sesh" address of a remote client
            //
            // If the optional is empty then the bool indicates whether this was an assertive
            // response (true; i.e. name does not exist or is invalid), or a failure getting/parsing
            // a lookup response (false).  (The bool will always be true for a positive response).
            //
            // The TTL indicates how long is remaining for the cached value before another lookup
            // will be needed.
            void resolve_sns(
                std::string name,
                std::function<void(std::optional<NetworkAddress>, bool assertive, std::chrono::milliseconds ttl)> func);

            void lookup_remote_srv(
                std::string name, std::string service, std::function<void(std::vector<dns::SRVData>)> handler);

            void lookup_relay_contact(RouterID remote, std::function<void(std::optional<RelayContact>)> func);

            void lookup_client_intro(
                RouterID remote,
                std::function<void(const std::optional<ClientContact>&)> func,
                bool allow_cache = true);

            // resolves any config mappings that parsed ONS addresses to their pubkey network address
            void resolve_sns_mappings();

            // Initiates a session to the given remote client or snode address.  Calls
            // `on_attempted` when the connection is either established (immediately, if a session
            // to the target is already established) or when the connection attempt times out (the
            // caller can check `session.is_established()` to figure out which one occurred).
            //
            // The timeout, if omitted/nullopt, defaults to the [paths]build-timeout config option.
            //
            // Note that this resulting session could be outbound or inbound: i.e. if the target is
            // a client (.sesh) that has already established a session to this Session Router instance then
            // that existing session is used rather than building a new outbound one.
            //
            // NB: this method can be safely called from outside the event loop (e.g. in embedded
            // usage).
            //
            // This method throws *without* calling `on_attempted` if a Session cannot be attempted,
            // such as when `remote` does not contain a valid pubkey.
            //
            // Returns nullptr if the remote is known to be unreachable, i.e. it is a relay for
            // which the network holds no relay contact.  `on_attempted`, if given, is still called
            // (with a non-established session) before returning, so a caller that only watches the
            // callback remains correct; the null return simply reports the same failure sooner.
            std::shared_ptr<session::Session> initiate_remote_session(
                const NetworkAddress& remote,
                std::function<void(session::Session& session)> on_attempted = nullptr,
                std::optional<std::chrono::milliseconds> timeout = std::nullopt);

            void tick(sys_ms now) override;

            void queue_session_packet(const NetworkAddress& remote, IPPacket pkt);

            void for_each_session(std::function<void(const NetworkAddress&, const session::Session&)> visit) const;

            session_tag next_tag();

            // Paths belonging to our outbound sessions.  These are used as extra RouterID fetch
            // sources when we do not have enough inbound paths of our own; unlike inbound paths,
            // whose terminals we pick at random, an outbound path's terminal was chosen to reach a
            // particular remote, so a caller should treat them as the less trustworthy source.
            std::vector<path::Path*> outbound_session_paths() const;

            // UDP port mapping, primarily for embedded clients.  This starts constructing a session
            // to the given remote, starts a UDP listener on an IPv6 localhost (i.e. `[::1]`) random
            // port, and sets up the internal handling so that UDP traffic to that UDP localhost
            // port will be forwarded to the remote (as well as return traffic from the remote
            // forwarded back to the address that sent data to the localhost port).
            //
            // Returns a pair:
            // - the port on [::1] where the application can send data to forward to the remote
            // - the outgoing session object (so that the caller can set an on_established hook, if
            //   desired).  Note that the session could change over time, e.g. if it is deleted by
            //   idle time out and then is re-established as a result of activity to this port.
            //
            // Returns nullopt, without mapping a port, if the remote is known to be unreachable
            // (see initiate_remote_session).  Mapping a port would be pointless in that case: no
            // session can carry what gets sent to it.
            //
            // Throws (via initiate_remote_session) if the Session could not be initiated, such as
            // when given an invalid pubkey in `remote`.
            std::optional<std::pair<uint16_t, std::shared_ptr<session::Session>>> map_udp_remote_port(
                const NetworkAddress& remote, uint16_t port);

            // Removes a mapping previously established with map_udp_remote_port; this closes the
            // socket and forgets any previous connection mappings.
            void unmap_udp_remote_port(const NetworkAddress& remote, uint16_t port);

            // TCP port mapping, for embedded clients.  This is the TCP counterpart of
            // map_udp_remote_port: it starts constructing a session to the given remote and listens
            // on an IPv6 localhost (i.e. `[::1]`) random port, where each connection the application
            // makes becomes one stream of a QUIC connection tunnelled through the session, and is
            // terminated by the remote into a TCP connection to `port` on its own tun address.
            //
            // Returns the same pair as map_udp_remote_port: the local port to connect to, and the
            // session (so a caller can hook its establishment).
            //
            // Returns nullopt, mapping nothing, if the remote is known to be unreachable, or if the
            // remote's client contact says it does not accept tunnelled TCP: no session could carry
            // what the port would receive.  A remote whose contact we do not have yet is *not*
            // refused here, since we cannot yet tell.
            //
            // Throws (via initiate_remote_session) if the session could not be initiated, such as
            // when given an invalid pubkey in `remote`.
            std::optional<std::pair<uint16_t, std::shared_ptr<session::Session>>> map_tcp_remote_port(
                const NetworkAddress& remote, uint16_t port);

            // Removes a mapping previously established with map_tcp_remote_port once its last
            // holder releases it, closing both the listener and any connections established through
            // it.  Not called directly by applications: the public API releases mappings by
            // destroying the tcp_tunnel claim that holds them.
            void unmap_tcp_remote_port(const NetworkAddress& remote, uint16_t port);
        };

    }  // namespace handlers
}  //  namespace srouter
