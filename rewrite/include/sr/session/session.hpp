#pragma once

#include <sr/crypto/aead.hpp>
#include <sr/crypto/mlkem.hpp>
#include <sr/crypto/sealed_box.hpp>
#include <sr/crypto/session_keys.hpp>
#include <sr/crypto/types.hpp>
#include <sr/path/path.hpp>

#include <atomic>
#include <cstdint>
#include <optional>
#include <vector>

namespace sr::session
{

    // Session tag: 4-byte identifier for multiplexing sessions on the same path.
    using SessionTag = std::array<std::byte, 4>;
    SessionTag random_tag();

    // Traffic types for session data messages.
    enum class TrafficType : uint8_t
    {
        IP = 0x01,
        Control = 0x02,
    };

    // Session represents an end-to-end encrypted channel between two nodes.
    // 1.1+ only: X25519 DH + ML-KEM-768 post-quantum key agreement.

    class Session
    {
      public:
        Session() = default;
        Session(const Session& o)
            : _keys{o._keys}, _tag{o._tag}, _established{o._established}, _nonce_counter{o._nonce_counter.load()} {}
        Session& operator=(const Session& o) {
            _keys = o._keys; _tag = o._tag; _established = o._established;
            _nonce_counter = o._nonce_counter.load(); return *this;
        }
        Session(Session&& o) noexcept
            : _keys{o._keys}, _tag{o._tag}, _established{o._established}, _nonce_counter{o._nonce_counter.load()} {}
        Session& operator=(Session&& o) noexcept {
            _keys = o._keys; _tag = o._tag; _established = o._established;
            _nonce_counter = o._nonce_counter.load(); return *this;
        }

        // Encrypt a data message with session keys.
        std::vector<std::byte> encrypt(std::span<const std::byte> plaintext, TrafficType type = TrafficType::IP) const;

        // Decrypt a data message. Returns nullopt if MAC fails.
        std::optional<std::vector<std::byte>> decrypt(std::span<const std::byte> ciphertext) const;

        bool is_established() const { return _established; }
        const SessionTag& tag() const { return _tag; }
        const sr::crypto::SessionKeys& keys() const { return _keys; }

        // Build from derived keys (after handshake completes)
        static Session from_keys(const sr::crypto::SessionKeys& keys, const SessionTag& tag);

      private:
        sr::crypto::SessionKeys _keys;
        SessionTag _tag{};
        bool _established = false;
        mutable std::atomic<uint64_t> _nonce_counter{0};
    };

    // Session handshake messages.
    // Initiator creates SessionInit, receiver creates SessionAccept.

    struct SessionInit
    {
        sr::crypto::Ed25519PubKey identity;
        sr::crypto::X25519PubKey x_pubkey;
        sr::crypto::MLKEMPubKey mlkem_pubkey;
        sr::crypto::Signature signature;
        SessionTag tag;

        // Serialize and seal for recipient
        std::vector<std::byte> seal_for(
            const sr::crypto::Ed25519PubKey& recipient, const sr::crypto::Ed25519SecKey& our_sk) const;

        // Unseal and parse
        static std::optional<SessionInit> unseal(
            std::span<const std::byte> sealed_data,
            const sr::crypto::Ed25519PubKey& our_pk,
            const sr::crypto::Ed25519SecKey& our_sk);
    };

    struct SessionAccept
    {
        sr::crypto::X25519PubKey x_pubkey;
        sr::crypto::MLKEMCiphertext mlkem_ciphertext;
        sr::crypto::Signature signature;
        SessionTag tag;

        std::vector<std::byte> seal_for(
            const sr::crypto::Ed25519PubKey& recipient, const sr::crypto::Ed25519SecKey& our_sk) const;

        static std::optional<SessionAccept> unseal(
            std::span<const std::byte> sealed_data,
            const sr::crypto::Ed25519PubKey& our_pk,
            const sr::crypto::Ed25519SecKey& our_sk);
    };

}  // namespace sr::session
