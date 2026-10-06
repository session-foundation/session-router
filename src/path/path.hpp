#pragma once

#include "address/types.hpp"
#include "constants/path.hpp"
#include "contact/client_intro.hpp"
#include "contact/relay_contact.hpp"
#include "crypto/crypto.hpp"
#include "transit_hop.hpp"
#include "util/time.hpp"

#include <chrono>
#include <functional>
#include <vector>

namespace oxen::quic
{
    struct message;
};

namespace srouter
{
    class Router;
    struct Profiling;

    namespace service
    {
        struct EncryptedIntroSet;
    }
}  // namespace srouter

namespace srouter::path
{
    /// Proxy object to produce a human readable hop list in log statements on demand.  This
    /// object is only intended to be used directly in format or log statements and not held.
    struct path_hop_stringifier
    {
        std::span<const TransitHop> hops;

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

    struct path_control_response
    {
        std::string body;
        bool timed_out{false};
        bool error{false};

        bool ok() { return !timed_out && !error; }
    };

    // The constant "type" values that we put on the end of control (stream) and data
    // (datagram) messages.  Data message can overlap since it comes on a different channel
    enum struct MessageType : unsigned char
    {
        Data = 0x01,

        CONTROL_MIN = 0x01,
        // Regular, session-encrypted control message:
        Control = 0x01,
        // SessionHandshake messages, which include session init, session accept, and path switch
        // messages (which are combined path switch + fallback session init messages).  NB: before
        // v1.1, these used to be exclusive used for path switch but not session init/accept.
        SessionHandshake = 0x02,
        CONTROL_MAX = 0x02,
    };

    class Path final : public std::enable_shared_from_this<Path>
    {
      public:
        Path(Router& rtr, std::span<const RelayContact> hop_rcs, sys_ms expiry_ts);

        // hops on constructed path
        std::vector<TransitHop> hops;

        // If set, this is an aligned path to a pivot and this value is the hopid required to
        // send data through the pivot.
        std::optional<HopID> aligned_hopid;

        // Constructs a ClientInfo from this path, i.e. for including in a client contact.
        ClientIntro make_intro() const;

        path_hop_stringifier hop_string() const;

        struct Info
        {
            // relay pubkeys and IPv4 addresses, from edge -> pivot (or final relay)
            std::vector<std::pair<RouterID, ipv4>> relays;
            sys_ms expiry = {};
            std::chrono::milliseconds ping_mean{0};
            std::chrono::microseconds ping_jitter{0};
            int ping_responses{0}, ping_timeouts{0}, ping_recent_timeouts{0};
        };
        Info get_info() const;

        sys_ms LastRemoteActivityAt() const { return last_recv_msg; }

        void do_ping(steady_ms start_time);

        size_t num_hops() const { return hops.size(); }

        const sys_ms& expiry() const { return _expiry; }

        std::chrono::milliseconds expires_in(sys_ms now = srouter::time_now_ms()) const { return _expiry - now; }

        bool is_expired(sys_ms now = srouter::time_now_ms()) const { return _expiry < now; }

        void resolve_sns(std::span<const std::byte, 32> name_hash, std::function<void(path_control_response)> func);

        void fetch_relay_contacts(std::span<const std::byte> body, std::function<void(path_control_response)> func);

        void find_client_contact(
            const PubKey& blinded_pk, int lookup_index, std::function<void(path_control_response)> func);

        void publish_client_contact(
            std::string_view enc_cc, int location, std::function<void(path_control_response)> func);

        void send_path_data_message(std::vector<std::byte>&& body, SymmNonce&& nonce = SymmNonce::make_random());

        void send_path_control_message(
            std::string_view method, std::span<const std::byte> body, std::function<void(path_control_response)> func);

        void send_session_control_message(
            std::vector<std::byte>&& body, SymmNonce&& nonce, MessageType type = MessageType::Control);

        // The overhead added to encrypted path messages (either data messages or path control
        // messages) by the `encrypt_path_message` function.  This is the amount that the
        // `payload` needs to be extended to add encryption metadata, and so callers can use
        // this value to reserve the vector to be able to store the overhead without additional
        // allocations.
        inline static constexpr size_t ENCRYPT_PATH_MESSAGE_OVERHEAD = SymmNonce::SIZE + HopID::SIZE + 1;
        inline static constexpr size_t ENCRYPT_PATH_MESSAGE_OVERHEAD_MAC =
            ENCRYPT_PATH_MESSAGE_OVERHEAD + crypto::TAG_SIZE;

        // Takes a payload and encrypts and extends it in-place to make it suitable for sending
        // down either the datagram channel (carrying traffic) or stream (carrying network
        // requests such as lookups or path builds).  This is *not* bt-encoded because we want
        // this to be as low overhead as possible for data messages, in particular.
        //
        // The given vector will be extended as part of this operation (to add nonce, hop,
        // packet type info).  To avoid a need for memory reallocation and copy, the caller
        // should optimally reserve enough space in the payload vector to ensure it has at least
        // ENCRYPT_PATH_MESSAGE_OVERHEAD additional bytes.
        //
        // nonce will be used if given, otherwise a random nonce is generated and used.  (It is
        // typically given when this is a session data message; see session.cpp).
        //
        // `type` must be a single byte, currently always equal to 0x01 for both data/control
        // messages.  (All other values are reserved for future versions of the protocol that
        // may need to change the fundamental structure of encrypted data, or send different
        // types of data)
        void encrypt_path_message(
            std::vector<std::byte>& payload, SymmNonce&& nonce, MessageType type, bool with_mac = false);

        std::string decrypt_path_message(std::string_view payload);

        bool is_active(sys_ms now = srouter::time_now_ms()) const { return _is_established && !is_expired(now); }

        const TransitHop& edge() const { return hops.front(); }
        const TransitHop& terminus() const { return hops.back(); }

        std::string name() const;

        bool operator==(const Path& other) const;

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;

        // The router ID at the end of the path.  For an outbound aligned path or inbound
        // session path, this is the pivot; for an outbound relay path this is the target relay.
        RouterID terminal_rid() const { return terminus().router_id; }

        // The hop ID of this path used by remotes who want to reach us.  I.e. this is the pivot
        // hopid we publish in client intros, and is used for return traffic on established
        // outbound sessions.
        HopID terminal_hopid() const { return terminus().txid; }

        void set_established();

        // Returns true if a path has been marked established.
        bool is_established() const { return _is_established; }

        // Marks a path as built.  This is primary used as a way to ensure we only build a Path
        // object once.  Returns true if the state was successfully changed (i.e. a false return
        // means the path was already built).
        bool set_built()
        {
            bool was_built = _is_built;
            _is_built = true;
            return not was_built;
        }

        // Returns true if a path has been marked as built.
        bool is_built() const { return _is_built; }

        // Will be true when the path has been discarded (such as when expiring, or after a
        // timeout); this is primarily used in the session code that hold onto the path as a shared
        // pointer (to avoid excessive weak_ptr locks) where the object might live a little longer
        // as a result, but uses this to detect when it should discard its pointer to the path as
        // well.
        bool is_dead{false};

        struct ping_stats_printer
        {
            Path& p;
            std::string to_string() const;
            static constexpr bool to_string_formattable = true;
        };

        // Returns ping stats: response rate (0.0-1.0), and average (successful) ping response time
        ping_stats_printer printable_ping_stats() { return ping_stats_printer{*this}; }

      private:
        /// call obtained exit hooks
        bool InformExitResult(std::chrono::milliseconds b);

        bool _is_built{false};
        bool _is_established{false};
        bool _is_dead{false};

        Router& _router;

        sys_ms _expiry{sys_ms::min()};
        sys_ms last_recv_msg{sys_ms::min()};

        static size_t next_path_log_id;
        const size_t path_log_id;  // Only used for log output

        steady_ms next_ping{};
        int ping_responses{0}, ping_timeouts{0};
        int ping_recent_timeouts{0};
        std::chrono::milliseconds ping_last{0ms};
        // Cumulative time of all `ping_responses` pings (divide by ping_responses for an average).
        std::chrono::milliseconds ping_cumulative{0ms};
        // This is the cumulative absolute differences of all received sequential pings.  E.g. if we
        // have 4 pings [100, 101, 98, 98] then this equals (|100-101| + |101-98| + |98-98|).
        // Dividing this by `ping_responses - 1` gives jitter.
        std::chrono::milliseconds ping_abs_diffs{0ms};
    };

}  // namespace srouter::path

template <>
struct std::hash<srouter::path::Path>
{
    size_t operator()(const srouter::path::Path& p) const noexcept
    {
        return hash<srouter::HopID>{}(p.terminal_hopid()) ^ ((hash<srouter::HopID>{}(p.edge().rxid) << 13) >> 5);
    }
};
