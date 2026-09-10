#pragma once

#include "address/address.hpp"
#include "constants/path.hpp"
#include "contact/client_contact.hpp"
#include "crypto/session_keys.hpp"
#include "ev/tcp.hpp"
#include "net/ip_packet.hpp"
#include "net/traffic_type.hpp"
#include "path/path.hpp"
#include "path/path_handler.hpp"
#include "path/transit_hop.hpp"

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/endpoint.hpp>

#include <chrono>
#include <queue>

namespace srouter
{
    namespace quic = oxen::quic;

    using recv_session_dgram_cb = std::function<void(std::span<std::byte>)>;

    inline constexpr auto SESSION_PATH_BUILD_ATTEMPTS{3};

    namespace link
    {
        class TunnelManager;
    }  //  namespace link

    namespace handlers
    {
        class SessionEndpoint;
    }  // namespace handlers

    namespace session
    {
        using session_tag = uint32_t;

        struct TCPTunnel;

        // We must not use the same nonce for path switch and session init, as they can be in the
        // same message using the same shared secret.  As such, the path switch message will use
        // dh_nonce ^ this xor factor.
        //
        // (Deprecated; this is only used in pre-1.1 session init).
        inline const SymmNonce switch_xor_factor = SymmNonce::filled<SymmNonce>(std::byte{0x42});

        // The following is our session initialization handshake procedure for a client with
        // (Ed25519) identity keypair (i,I) initiating a session to a remote with identity keypair
        // (r,R).
        //
        // We establish a perfect forward secret session key as follows:
        //
        // 1. Session initialization message:
        //
        //    a) The initiator generates ephemeral X25519 (x, X) and ML-KEM768 (m, M) keypairs for
        //       establishing a session secret.  These are stored until the session is fully
        //       established.
        //
        //    b) The remote's Ed25519 pubkey (R) is converted to a X25519 pubkey (Rx), so that we
        //       can use standard libsodium xchacha20 sealed box encryption.
        //
        //    c) We encrypt the following Session initialization parameters using that sealed box
        //       encryption:
        //       - session ephemeral X25519 pubkey (X)
        //       - session ephemeral ML-KEM768 pubkey (M)
        //       - our Ed25519 client pubkey (aka "identity") (I)
        //       - our (current) pivot hopid, for routing traffic back to us through the aligned
        //         pivot (i.e. the pivot through which the message arrived).
        //       - unique 32-bit tag to identify incoming data for this session (tagᵢ).
        //       - signature over all of the above using the initiator's identity keypair, i/I.
        //
        //    The session initiation message body then consists of (bt-encoded):
        //
        //        ""="i", // session handshake identifier.  Omitted implies the earlier (1.0.x) DF
        //                // exchange, while "i" indicates this PFS/PQ key exchange.  Any other
        //                // value is reserved for future use.
        //        B=sealed box
        //
        // 2. Session initialization recipient and reply:
        //
        //    a) Decrypts the sealed box using the X25519 secret key (rx) derived from the long-term
        //       identity key (r), obtaining the initialization parameters (X, M, I, etc.)
        //
        //    b) Validates the inner identity (I) and signature.
        //
        //    c) Generates an ephemeral X25519 keypair (y, Y).  This keypair is only stored
        //       momentarily (i.e. it does not need to be stored beyond sending the session
        //       acceptance message).
        //
        //    d) Generate and encapsulate a random, 32-byte ML-KEM768 shared secret (kₛ),
        //       encapsulated for the client's ML-KEM pubkey M, producing ML-KEM768 ciphertext (ct).
        //
        //    e) Generates a unique 32-bit session tag (tagᵣ) to identify incoming data for this
        //       session.
        //
        //    f) Generates the two final 32-byte session symmetric keys:
        //
        //        context = blake2b_64(I || R || tagᵢ || tagᵣ, key="srouter session context")
        //
        //        [kᵢₙ, kₒᵤₜ] = blake2b_64(yX || X || Y || kₛ || M, key=context)
        //
        //       where tagᵢ and tagᵣ are 4-byte, little-endian encodings of the initiator's and
        //       responder's tags, respectively, and everything else is in its standard byte
        //       representation.
        //
        //       This yields two encryption keys: kᵢₙ for decrypting incoming session data, and kₒᵤₜ
        //       for encrypting outgoing session data.
        //
        //    g) A response payload is constructed containing:
        //
        //        "Y": server ephemeral session x25519 pubkey (Y),
        //        "c": MLKEM ciphertext (ct),
        //        "t": recipient session tag (tagᵣ)
        //        "~": Long-term identity Ed25519 signature over all of the above encoded data
        //
        //    h) A sealed box encryption identical to the one in session init is then used to
        //       encrypt the response payload data for the initiator (but this time encrypting for
        //       Ix, the X25519 pubkey derived from the initiator's Ed25519 pubkey, I).  The session
        //       response message body thus consists of:
        //
        //           ""="a", // X25519+PQ session accept identifier
        //           B=sealed box
        //
        //       (Note that this is not yet using session encryption keys as the initiator still
        //       needs this data to construct the final session keys).
        //
        //    From the recipient's perspective, the session is now established, and all future
        //    messages on this established session will be encrypted/decrypted with kₒᵤₜ/kᵢₙ.
        //
        // 3. The session initiator receives the session confirmation message from the remote,
        //    decrypts the sealed box, verifies the signature within it, and extracts the various
        //    fields.  From this it then recovers:
        //
        //        kₛ = Decapsulate(m, ct)
        //
        //    and then computes the final session symmetric keys as done in the server (but with yX
        //    swapped for xY, and swapped order for kₒᵤₜ, kᵢₙ since "in" and "out" directions are
        //    reversed relative to the remote).
        //
        //    It then discards the ephemeral x/X and m/M keypairs; the session is now established.
        //
        // At this point the session is established, with perfect forward secret keys for the
        // session keys in each direction.

        class Session
        {
            // TODO FIXME: how long since last use should is_expired() return true?
            static constexpr std::chrono::milliseconds SESSION_TIMEOUT = 30s;

            friend struct TCPTunnel;
            template <typename T>
            friend bool check_dead(std::shared_ptr<T>& path_like, Session& s);

          protected:
            Router& _r;
            handlers::SessionEndpoint& _parent;

            // The session tags.  Each side of the session decides its own inbound tag, meaning
            // no worries about collision *and* shorter tags on each packet.  Outbound tag starts
            // out at 0, which is a magic value that gets used for session_init and is updated when
            // we get back the session_accept.
            session_tag _inbound_tag;
            session_tag _outbound_tag{0};

            NetworkAddress _remote;

            // Deprecated; to be removed once all relays are running Session Router 1.1.0+ (and thus
            // using PFS ephemeral keys).  When either party is still running 1.0.x this get used:
            std::optional<SymmKey> _shared_secret;
            // When we have issued a session init but not yet received the response, this will be
            // set.  This is used, in particular, for the new embedded ephemeral key in a PathSwitch
            // so we don't actually switch to it unless the other side gives a session accept.
            std::optional<SymmKey> _pending_shared_secret;

            // The (PQ, PFS) keys used for inbound and outbound packet encryption.  These are
            // established during the session initiation handshake (see longer comments above).
            std::optional<SymmKey> _inbound_key;
            std::optional<SymmKey> _outbound_key;

            // used for bridging data messages across aligned paths
            HopID _remote_pivot_txid;

            // Will be set to true when an outbound session is established; will always be true for
            // inbound sessions.
            bool _is_established{false};

            // Will be set to true if this session has been closed (i.e. via a call to
            // SessionEndpoint::close_session).  Closing is terminal (i.e. a closed Session instance
            // will never become non-closed; reestablishing a closed Session requires replacing it).
            bool _is_closed{false};

            // Will be set to true if we determine that this session can never be established,
            // as opposed to merely not having established yet.  Currently this means the remote
            // is a relay for which the network has no relay contact: we know how to reach any
            // relay we hold an RC for, and we hold RCs for all of them, so a missing RC means the
            // relay is not participating in the network at all.
            bool _unreachable{false};

            // Set to true if our current path is definitely dead, to short-circuit things like
            // send_session_message encryption if we know we can't deliver it anywhere.  This
            // is roughly equivalent to `!path || path->is_dead`, except that the base class doesn't
            // know about `path` and so this allows subclasses the provide the information back to
            // the base class without needing an extra virtual method call on every packet.
            //
            // Base classes should reset this to false as soon as they switch to a new path.
            bool _dead_path{true};

            std::unique_ptr<TCPTunnel> tcp_tunnel{nullptr};

            sys_ms last_activity = srouter::time_now_ms();

            // only currently useful for outbound client sessions, but more convenient here
            // than an overload on all inbound traffic functions for that one case
            sys_ms last_inbound_activity = srouter::time_now_ms();

            void update_active();

            // We always map ipv6 address for remotes, but ipv4 address are only mapped on demand
            // (i.e. by requesting a "ipv4.pubkey.sesh" address on the initiator, or by receiving an
            // IPv4 packet from the remote).  This variable caches/tracks whether we've already done
            // that assignment to avoid needing an address map lookup on every IPv4 packet.
            bool ipv4_mapped{false};

            // We capture a weak_ptr to this shared_ptr to avoid needing to use shared_from_this
            // when we need to assure we are still alive in lambdas given to external objects.  I.e.
            // this allows: `[alive=canary(), this] { if (!alive.lock()) return; ... }`
            std::shared_ptr<bool> _destructor_canary{std::make_shared<bool>(true)};
            std::weak_ptr<bool> canary() { return _destructor_canary; }

            Session(
                Router& r, handlers::SessionEndpoint& parent, const NetworkAddress& remote, session_tag inbound_tag);

            Session(Router& r, handlers::SessionEndpoint& parent);

            virtual void handle_client_contact(std::span<const std::byte> payload);

            virtual ~Session();

          public:
            // Non-movable, non-copyable:
            Session(Session&&) = delete;
            Session(const Session&) = delete;
            Session& operator=(Session&&) = delete;
            Session& operator=(const Session&) = delete;

            // True if this is an OutboundSession-derived instance.
            const bool is_outbound;

            // True if this is a session instance between a client and relay (i.e. either
            // InboundRelaySession- or OutboundRelaySession-derived).
            const bool is_relay_session;

            // TODO FIXME: make this do something.  When the session establishes we should get some
            // capabilities metadata, such as whether it supports exit.
            const bool is_exit_capable{false};

            const NetworkAddress& remote() const { return _remote; }

            std::string encode_session_control_message(
                std::string_view method,
                std::span<const std::byte> body,
                const SymmNonce& nonce,
                std::optional<HopID> pivot_id);

            // Attempts to send a session control message down the current path.  Returns false
            // (without calling `func`) if there is no current session or path, otherwise sends it
            // and returns true.
            void send_session_control_message(std::string_view method, std::span<const std::byte> body);

            // Sends a special session control message that is pre-encrypted for messages that are
            // actionable before session keys are (or might be) established, such as session init,
            // session accept, and path switch messages.  No encryption is applied by this (i.e. the
            // body should be pre-encrypted as needed).
            void send_session_precontrol_message(std::span<const std::byte> body, path::MessageType mtype);

            void recv_session_control_message(
                std::vector<std::byte>&& message,
                const SymmNonce& nonce,
                std::variant<std::shared_ptr<path::TransitHop>, std::shared_ptr<path::Path>> source);

            // Deprecated: for handling pre-PFS session accept:
            virtual void handle_session_accept_deprecated(std::span<const std::byte> params);

            // Sends a data message (i.e. datagram)
            void send_session_data_message(std::span<const std::byte> data, traffic_type type);
            void send_session_data_message(std::span<const std::byte> data, net::IPProtocol proto)
            {
                send_session_data_message(data, to_traffic_type(proto));
            }

            // This is the implementation function for cooking session spagh^Wmessages, used by both
            // data and control messages.  It has several different tweaks, for accomodating the
            // various slightly different ways in which it is built, but the *core* of all those
            // constructions is largely similar, hence this one spaghetti function with options for
            // pasta shape, gluten free, sauce, cheese, and freshly ground pepper.
            std::optional<std::pair<std::vector<std::byte>, SymmNonce>> make_session_message(
                std::span<const std::byte> data,
                // data_type is for data messages, and must be nullopt for control messages:
                std::optional<traffic_type> data_type,
                // Can be false to disable session encryption, for use with pre-encrypted data that
                // use custom encryption, such as path switch and session handshake messages:
                bool encrypt = true);

            virtual void send_path_data_message(std::vector<std::byte>&& data, SymmNonce&& nonce) = 0;
            virtual void send_path_control_message(
                std::vector<std::byte>&& data, SymmNonce&& nonce, path::MessageType type) = 0;

            // Called by send_session_data_message if trying to send a data message on a
            // not-yet-established connection (which, by definition, can only be an outbound
            // session).  The default does nothing, but OutboundSession overrides to queue them (up
            // to a limit) so that initially sent packets on an initializing session get delivered
            // as soon as the session establishes.  This allows, for example, pings to get delivered
            // rather than having the first couple getting dropped before establishing.
            virtual void queue_data_message(std::span<const std::byte> /*data*/, traffic_type /*type*/) {}

            void recv_session_data_message(std::vector<std::byte> data, const SymmNonce& nonce);

            void publish_client_contact(std::string_view encrypted_cc);

            void handle_udp_from_remote(IPPacket&& pkt);

            // Returns this session's TCP tunnel, constructing it on first use: most sessions never
            // carry tunnelled TCP and should not pay for a QUIC endpoint they will not use.
            TCPTunnel& tunnel();

            // The TCP tunnel if this session has one, without creating one.
            TCPTunnel* maybe_tunnel() { return tcp_tunnel.get(); }

            // Whether the remote advertises that it can terminate tunnelled TCP streams.  nullopt
            // means we have no client contact for the remote yet and so cannot tell, in which case a
            // caller may go ahead and find out the hard way.
            virtual std::optional<bool> remote_accepts_tcp() const { return std::nullopt; }

            // Returns true if this session is established, and has not been explicitly closed.
            // Inbound sessions are instantly established; outbound sessions are established once
            // the session init response arrives from the remote.
            bool is_established() const;

            // Returns true if this session is established, and is using PFS+PQ keys.  False if not
            // established, or if using pre-PFS key exchange keys.  (This can be deleted once we
            // drop pre-PFS key exchange support).
            bool is_established_pfs() const { return _inbound_key.has_value(); }

            session_tag inbound_tag() const { return _inbound_tag; }
            session_tag outbound_tag() const { return _outbound_tag; }

            // Returns true if this session has been closed, i.e. it is in the middle of shutting
            // down.
            bool is_closed() const { return _is_closed; }

            // Returns true if this session is known to be impossible to establish, rather than
            // simply not established yet.  Such a session must not be reused: a later attempt on
            // the same remote should build a fresh one, as the information that made this one
            // unreachable (currently: a missing relay contact) can change.
            bool is_unreachable() const { return _unreachable; }

            // Called to close this session.  If the bool is true then the session will attempt to
            // send a session_close control message down the active path.
            void close(bool send_close);

            virtual void recv_close();

            bool is_expired(sys_ms now) const;

            virtual std::string to_string() const = 0;

            static constexpr bool to_string_formattable = true;

            // Called periodically (somewhere under Router::tick) to handle anything needed on the
            // session, but also sometimes called in other places (e.g. if we need new paths ASAP
            // rather than waiting for the next tick)
            virtual void tick(sys_ms now);

            virtual path::Path::Info current_path_info() const { return {}; };
        };

        class OutboundSession : public path::PathHandler, public Session
        {
          protected:
            std::shared_ptr<path::Path> _current_path;

            // PFS ephemeral keys; these are held only by the initiator during session
            // initialization as they are needed to process the response to derived the session
            // shared secret.  (Inbound sessions do not need these at all as the keys used there are
            // only needed during processing of the inbound session request itself, unlike outbound
            // sessions that have to hold them awaiting a session initialization response).
            //
            // As soon as the session is successfully negotiated (i.e. once we resolve the final
            // session shared secret) these are zeroed out.
            std::optional<MLKEM768KeyPair> _session_mlkem756;
            std::optional<X25519KeyPair> _session_x25519;

            OutboundSession(
                const NetworkAddress& remote,
                handlers::SessionEndpoint& parent,
                int num_hops,
                session_tag inbound_tag,
                std::function<void(OutboundSession& session)> on_established,
                std::optional<std::chrono::milliseconds> establish_timeout = std::nullopt);

            ~OutboundSession() override = default;

            void select_new_current_impl(
                std::vector<std::pair<path::Path*, HopID>>&& good,
                std::vector<std::pair<path::Path*, HopID>>&& fallback);

            void tick(sys_ms now) override;

            virtual void select_new_current() = 0;

            // Closes non-active paths that are close to expiry, i.e. any paths that we would not
            // select if we need to switch paths.
            void close_old_paths(sys_ms now);

            void send_path_data_message(std::vector<std::byte>&& data, SymmNonce&& nonce) override;
            void send_path_control_message(
                std::vector<std::byte>&& data, SymmNonce&& nonce, path::MessageType type) override;

            void queue_data_message(std::span<const std::byte>, traffic_type type) override;

            // Marks the session unreachable and fires every waiting on_established callback right
            // away rather than letting each one sit until its own deadline.  For a session we know
            // can never establish, the deadline would only be telling the caller something we
            // already know.
            void mark_unreachable();

            // We stash the `type` as the last byte of the vector
            std::optional<std::deque<std::vector<std::byte>>> pre_establish_data_queue;

            virtual bool use_old_init() const = 0;

          private:
            // Switches to (or starts using) the given path.
            void switch_path(path::Path& p, const HopID& new_pivot_txid);

            std::pair<std::string, path::MessageType> make_session_init(path::Path& path);

            void fire_waiting();

            using active_item = std::pair<steady_ms, std::function<void(OutboundSession& session)>>;
            struct on_established_sorter
            {
                bool operator()(const active_item& a, const active_item& b) const { return a.first > b.first; }
            };
            // Callbacks that we fire once we establish or fail; see on_established()
            std::priority_queue<active_item, std::vector<active_item>, on_established_sorter> _on_established;

            void on_path_build_success(int64_t build_id, path::Path& p) override;

            void on_path_build_failure(int64_t build_id, path::Path* p, bool timeout) override;

            void handle_session_accept_deprecated(std::span<const std::byte> params) override;

          public:
            // void stop_session() override;

            // Calls the given callback with the session when it becomes established, or after
            // timing out.  (The callback can check which case occurred via `.is_established()` on
            // the argument).  If the session is already established when this is called then it is
            // fired immediately (before returning).
            //
            // If the timeout is omitted then it defaults to the config
            // [network]path-alignment-timeout setting.
            //
            // Multiple callbacks waiting on the same session are permitted.
            void on_established(
                std::function<void(OutboundSession&)> callback,
                std::optional<std::chrono::milliseconds> timeout = std::nullopt);

            // Processes a session accept SessionHandshake message.  The initial "":"a" keypair
            // (indicating that this was an accept message) will already have been consumed from the
            // given bt_dict_consumer.
            void handle_session_accept(oxenc::bt_dict_consumer&& payload);

            std::string to_string() const override;

            inline static constexpr int MAX_QUEUED_PACKETS = 30;

            path::Path::Info current_path_info() const override;
        };

        // Outbound Session to Remote Relay
        class OutboundRelaySession final : public OutboundSession
        {
          public:
            OutboundRelaySession(
                const NetworkAddress& remote,
                handlers::SessionEndpoint& parent,
                session_tag inbound_tag,
                std::function<void(OutboundSession& session)> on_established,
                std::optional<std::chrono::milliseconds> establish_timeout = std::nullopt);

            void update_paths(sys_ms now) override;

            void recv_close() override;

            // void stop(bool send_close = false) override;

          private:
            void select_new_current() override;
            bool use_old_init() const override;
        };

        // Outbound Session to Remote Client
        class OutboundClientSession final : public OutboundSession
        {
          public:
            OutboundClientSession(
                const NetworkAddress& remote,
                handlers::SessionEndpoint& parent,
                session_tag inbound_tag,
                std::function<void(OutboundSession& session)> on_established,
                std::optional<std::chrono::milliseconds> establish_timeout = std::nullopt);

            // Constants controlling when we re-fetch a CC:

            // Re-fetch if our current CC gets this old:
            static constexpr auto CC_FETCH_STALE = 10min;

            // Linear backoff parameters: each time a CC fetch fails, we schedule a refetch in
            // CC_FETCH_BACKOFF times the number of sequential failures, up to a max of
            // CC_FETCH_BACKOFF_MAX.
            static constexpr std::chrono::milliseconds CC_FETCH_BACKOFF = 990ms;
            static constexpr std::chrono::milliseconds CC_FETCH_BACKOFF_MAX = 10s;

          private:
            std::vector<ClientIntro> _intros;
            std::unordered_set<RouterID> _pivots;
            bool _intro_update_processed = false;
            bool _updating_intros = false;

            sys_ms _next_cc_update{};
            int _cc_fetch_fail_count = 0;
            bool _cc_ok = false;

            // Tracks the signed-at value whenever we update CC values: if we receive a session
            // close message then that tells us we need to wait for a CC newer than this before we
            // can rebuild paths to reestablish the session.
            sys_ms _cc_last_signed{};

            protocol_flag _cc_protos = protocol_flag::NONE;

            // Chooses the next router id to pivot to, based on introset and current paths.  Returns
            // nullopt if no pivot is available right now, otherwise the router id and the lifetime
            // of paths to that pivot (so that we avoid creating paths that will become stale paths
            // living beyond the expiry of the pivot).
            std::optional<std::pair<RouterID, std::pair<std::chrono::seconds, HopID>>> select_pivot();

            void select_new_current() override;
            bool use_old_init() const override;
            std::optional<bool> remote_accepts_tcp() const override;

          protected:
            void handle_client_contact(std::span<const std::byte> payload) override;

          public:
            // Initiates a client intro lookup via the session endpoint.  This can be called even if
            // there already is intros, to refresh/replace them.
            void refresh_intros();

            void tick(sys_ms now) override;

            // Called with a client contact to replace the current set of client intros used by this
            // session with the ones in the given client contact.  This is called by
            // `refresh_intros()` upon a success fetch, but can also be called externally (such as
            // when receiving intro updates through an existing session).
            void update_intros(const ClientContact& cc);

            void update_paths(sys_ms now) override;

            void recv_close() override;

            const RouterID& remote_endpoint() const { return _remote.pubkey; }
        };

        class InboundSession : public Session
        {
          protected:
            InboundSession(handlers::SessionEndpoint& parent);

            ~InboundSession() override = default;

            void init(std::span<const std::byte> request);

            // Deprecated handler for pre-1.1 session initialization
            void init_legacy(oxenc::bt_dict_consumer& outer_btdc);

            // The session accept message to be sent back to the initiator.  This is populated
            // during construction and then cleared after being actually sent (by calling
            // session_init_accept).
            std::string _accept_msg;

            // Will be true if this is a single-DH message that uses normal session encryption for a
            // SR 1.0.x handshake.  This is deprecated and to be removed.
            bool _old_accept = false;

            // protocol flags advertised by the initiator in the (1.1+) session init:
            protocol_flag protos;

          public:
            // Called at the end of session initialization, after Session setup housecleaning is
            // done, to actually send the session accept generating early in session init by
            // `init()`.
            void session_init_accept();
        };

        // Inbound Session *to* client from client (we are the target client)
        class InboundClientSession final : public InboundSession
        {
            std::shared_ptr<path::Path> _current_path;

            void send_path_data_message(std::vector<std::byte>&& data, SymmNonce&& nonce) override;
            void send_path_control_message(
                std::vector<std::byte>&& data, SymmNonce&& nonce, path::MessageType type) override;

          public:
            InboundClientSession(
                handlers::SessionEndpoint& parent, std::shared_ptr<path::Path> p, std::span<const std::byte> request);

            void handle_path_switch(HopID pivot, std::shared_ptr<path::Path> path);

            path::Path::Info current_path_info() const override;

            std::string to_string() const override;
        };

        // Inbound Session *to* relay from client (we are the target relay)
        class InboundRelaySession final : public InboundSession
        {
            std::shared_ptr<path::TransitHop> _current_thop;

            void encrypt_path_message(std::vector<std::byte>& data, SymmNonce&& nonce, path::MessageType type);

            void send_path_data_message(std::vector<std::byte>&& data, SymmNonce&& nonce) override;

            void send_path_control_message(
                std::vector<std::byte>&& data, SymmNonce&& nonce, path::MessageType type) override;

          public:
            InboundRelaySession(
                handlers::SessionEndpoint& parent,
                std::shared_ptr<path::TransitHop> thop,
                std::span<const std::byte> request);

            void handle_path_switch(HopID pivot, std::shared_ptr<path::TransitHop> thop);

            std::string to_string() const override;
        };

#if defined(__GNUG__) && !defined(__clang__) && __GNUG__ <= 10
        // Workaround for gcc-10: our stock quic::ToStringFormattable fails under gcc-10 for
        // abstract classes, so this workaround formatter gets used instead to make it work.
        template <typename T>
        struct gcc_session_formatter : fmt::formatter<std::string_view>
        {
            template <typename FormatContext>
            auto format(const T& val, FormatContext& ctx) const
            {
                return formatter<std::string_view>::format(val.to_string(), ctx);
            }
        };
#endif

    }  // namespace session

}  // namespace srouter

#if defined(__GNUG__) && !defined(__clang__) && __GNUG__ <= 10
// gcc-10 workaround: see above
namespace fmt
{
    template <>
    struct formatter<srouter::session::OutboundSession>
        : srouter::session::gcc_session_formatter<srouter::session::OutboundSession>
    {};
}  // namespace fmt
#endif
