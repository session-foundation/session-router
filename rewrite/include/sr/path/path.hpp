#pragma once

#include <sr/crypto/aead.hpp>
#include <sr/crypto/types.hpp>
#include <sr/path/hop.hpp>

#include <chrono>
#include <optional>
#include <vector>

namespace sr::path
{

    // Path represents a client-side onion route through multiple relays.
    // The client knows all hops and their shared secrets.

    class Path
    {
      public:
        Path() = default;
        explicit Path(
            std::vector<Hop> hops, std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now());

        // Encrypt a message for sending down the path (client → pivot).
        // Applies onion layers in REVERSE order (pivot first, edge last).
        // Returns the encrypted message with nonce + hop metadata appended.
        std::vector<std::byte> encrypt_data(std::span<const std::byte> plaintext, const sr::crypto::Nonce& nonce) const;

        // Decrypt a message received from the path (pivot → client).
        // Peels onion layers in FORWARD order (edge first, pivot last).
        std::optional<std::vector<std::byte>> decrypt_data(std::span<std::byte> data, sr::crypto::Nonce& nonce) const;

        // Accessors
        const std::vector<Hop>& hops() const { return _hops; }
        size_t hop_count() const { return _hops.size(); }
        const Hop& edge() const { return _hops.front(); }
        const Hop& pivot() const { return _hops.back(); }

        bool is_expired(std::chrono::steady_clock::time_point now) const;
        bool is_established() const { return _established; }
        void set_established() { _established = true; }

        // Path lifetime: 20 minutes + 0-3 minutes random fuzz
        static constexpr auto MAX_LIFETIME = std::chrono::minutes(20);
        static constexpr auto MAX_FUZZ = std::chrono::minutes(3);

      private:
        std::vector<Hop> _hops;
        std::chrono::steady_clock::time_point _created;
        std::chrono::seconds _lifetime_fuzz{0};
        bool _established = false;
    };

}  // namespace sr::path
