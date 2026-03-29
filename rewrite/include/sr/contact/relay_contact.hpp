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
    // Wire format: BT-encoded dict with fields 4, p, t, v, ~

    struct RelayAddress
    {
        uint32_t ipv4 = 0;  // network byte order
        uint16_t port = 0;  // host byte order
    };

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

        // Parse from BT-encoded bytes
        static std::optional<RelayContact> from_bt(std::span<const std::byte> data);

        // Serialize to BT-encoded bytes (without signature)
        std::vector<std::byte> to_bt_unsigned() const;

        // Sign with relay's secret key
        void sign(const sr::crypto::Ed25519SecKey& sk);

        // Verify the signature
        bool verify() const;

        // Check if RC is too old (expired)
        bool is_expired(
            std::chrono::system_clock::time_point now, std::chrono::seconds max_age = std::chrono::hours(1)) const;

        // Accessors
        const RouterID& router_id() const { return _rid; }
        const RelayAddress& address() const { return _addr; }
        std::chrono::system_clock::time_point timestamp() const { return _timestamp; }
        const std::array<uint8_t, 3>& version() const { return _version; }
        const sr::crypto::Signature& signature() const { return _sig; }

        bool operator==(const RelayContact&) const = default;

      private:
        RouterID _rid;
        RelayAddress _addr;
        std::array<uint8_t, 3> _version{0, 10, 0};
        std::chrono::system_clock::time_point _timestamp;
        sr::crypto::Signature _sig{};
    };

}  // namespace sr::contact
