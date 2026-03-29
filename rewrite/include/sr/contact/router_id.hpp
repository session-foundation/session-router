#pragma once

#include <sr/crypto/types.hpp>

#include <functional>
#include <string>

namespace sr::contact
{

    // RouterID identifies a relay on the network.
    // It's an Ed25519 public key with comparison, hashing, and string conversion.

    class RouterID
    {
      public:
        RouterID() = default;
        explicit RouterID(const sr::crypto::Ed25519PubKey& pk) : _pk{pk} {}
        explicit RouterID(std::span<const std::byte, 32> data);

        const sr::crypto::Ed25519PubKey& pubkey() const { return _pk; }
        const std::byte* data() const { return _pk.data(); }
        static constexpr size_t size() { return 32; }

        // Hex string representation
        std::string to_string() const;
        static RouterID from_string(std::string_view hex);

        bool operator==(const RouterID&) const = default;
        auto operator<=>(const RouterID&) const = default;

      private:
        sr::crypto::Ed25519PubKey _pk{};
    };

}  // namespace sr::contact

// Hash for use in unordered containers
template <>
struct std::hash<sr::contact::RouterID>
{
    size_t operator()(const sr::contact::RouterID& rid) const noexcept
    {
        size_t h = 0;
        auto* p = reinterpret_cast<const size_t*>(rid.data());
        for (size_t i = 0; i < 32 / sizeof(size_t); ++i)
            h ^= p[i];
        return h;
    }
};
