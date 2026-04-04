#pragma once

#include <sr/contact/router_id.hpp>
#include <sr/crypto/types.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sr::contact
{

    // RelayContact is the signed advertisement a relay publishes.
    // Contains address, port, version, and the relay's Ed25519 signature.
    //
    // Wire format: BT-encoded dict with fields:
    //   ""  -> RC version (uint8, 0 or omitted = version 0)
    //   "#" -> network ID (int, 0/omitted = mainnet, 1 = testnet)
    //   "4" -> IPv4 (4 bytes) + port (2 bytes BE)
    //   "6" -> IPv6 (16 bytes) + port (2 bytes BE) [optional]
    //   "p" -> Ed25519 pubkey (32 bytes)
    //   "t" -> timestamp (uint64, seconds since epoch)
    //   "v" -> version (3 bytes: MAJOR, MINOR, PATCH)
    //   "~" -> Ed25519 signature (64 bytes)

    struct RelayAddress
    {
        uint32_t ipv4 = 0;  // network byte order
        uint16_t port = 0;  // host byte order
    };

    struct IPv6Address
    {
        std::array<uint8_t, 16> addr{};
        uint16_t port = 0;  // host byte order
        bool present = false;
    };

    // Validation constants
    inline constexpr size_t RC_MAX_SIZE = 2048;
    inline constexpr auto RC_MAX_AGE = std::chrono::hours(24 * 30);  // 30 days
    inline constexpr auto RC_OUTDATED_THRESHOLD = std::chrono::hours(12);

    class RelayContact
    {
      public:
        RelayContact() = default;

        // Construct from components
        RelayContact(
            const RouterID& rid,
            const RelayAddress& addr,
            std::array<uint8_t, 3> version,
            std::chrono::system_clock::time_point timestamp);

        // Parse from BT-encoded bytes (single RC)
        static std::optional<RelayContact> from_bt(std::span<const std::byte> data);

        // Parse bootstrap file: single RC dict or list of RC dicts
        // Detects format by first byte: 'l' = list, 'd' = single
        static std::vector<RelayContact> from_bootstrap(std::span<const std::byte> data);

        // Serialize to BT-encoded bytes (without signature)
        std::vector<std::byte> to_bt_unsigned() const;

        // Serialize to full BT with signature
        std::vector<std::byte> to_bt_signed() const;

        // Sign with relay's secret key
        void sign(const sr::crypto::Ed25519SecKey& sk);

        // Verify the signature
        bool verify() const;

        // Check if RC is too old (expired)
        bool is_expired(
            std::chrono::system_clock::time_point now, std::chrono::seconds max_age = std::chrono::hours(1)) const;

        // Check if RC is outdated (stale but not expired)
        bool is_outdated(std::chrono::system_clock::time_point now) const;

        // Accessors
        const RouterID& router_id() const { return _rid; }
        const RelayAddress& address() const { return _addr; }
        const IPv6Address& ipv6() const { return _ipv6; }
        std::chrono::system_clock::time_point timestamp() const { return _timestamp; }
        const std::array<uint8_t, 3>& version() const { return _version; }
        const sr::crypto::Signature& signature() const { return _sig; }
        uint8_t rc_version() const { return _rc_version; }
        int network_id() const { return _network_id; }

        // Setters for optional fields
        void set_ipv6(const IPv6Address& v6) { _ipv6 = v6; }
        void set_network_id(int id) { _network_id = id; }
        void set_rc_version(uint8_t v) { _rc_version = v; }

        bool operator==(const RelayContact&) const = default;

      private:
        RouterID _rid;
        RelayAddress _addr;
        IPv6Address _ipv6;
        std::array<uint8_t, 3> _version{0, 10, 0};
        std::chrono::system_clock::time_point _timestamp;
        sr::crypto::Signature _sig{};
        uint8_t _rc_version = 0;
        int _network_id = 0;  // 0 = mainnet, 1 = testnet
    };

}  // namespace sr::contact
