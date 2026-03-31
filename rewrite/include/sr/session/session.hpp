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
#include <string>
#include <vector>

namespace sr::session
{

    // Session tag: 4-byte identifier for multiplexing sessions on the same path.
    using SessionTag = std::array<std::byte, 4>;
    SessionTag random_tag();

    // Convert between SessionTag (4 bytes) and uint32_t (little-endian)
    uint32_t tag_to_uint(const SessionTag& tag);
    SessionTag uint_to_tag(uint32_t val);

    // Traffic types for session data messages.
    enum class TrafficType : uint8_t
    {
        IP = 0x01,
        Control = 0x02,
    };

    // Message types for path framing layer.
    enum class MessageType : uint8_t
    {
        DataOrControl = 0x01,
        SessionHandshake = 0x02,
    };

    // Pivot ID: 16-byte identifier for the pivot hop
    using PivotID = sr::crypto::Bytes<16>;

    // Session represents an end-to-end encrypted channel between two nodes.
    // 1.1+ only: X25519 DH + ML-KEM-768 post-quantum key agreement.

    class Session
    {
      public:
        Session() = default;

        // Sessions are MOVE-ONLY. Copying would duplicate the nonce counter,
        // causing nonce reuse which breaks AEAD security.
        Session(const Session&) = delete;
        Session& operator=(const Session&) = delete;
        Session(Session&& o) noexcept
            : _keys{o._keys}, _tag{o._tag}, _pivot_id{o._pivot_id},
              _established{o._established}, _nonce_counter{o._nonce_counter.exchange(0)} {}
        Session& operator=(Session&& o) noexcept {
            _keys = o._keys; _tag = o._tag; _pivot_id = o._pivot_id;
            _established = o._established;
            _nonce_counter = o._nonce_counter.exchange(0); return *this;
        }

        // Encrypt a data message with session keys.
        // Returns: [Encrypted(PAYLOAD + TYPE_BYTE)] [SESSION_TAG 4 bytes BE] [PIVOT_ID 16 bytes]
        // Nonce is NOT included — it belongs in the path framing layer.
        std::vector<std::byte> encrypt(
            std::span<const std::byte> plaintext,
            const sr::crypto::Nonce& nonce,
            TrafficType type = TrafficType::IP) const;

        // Decrypt a data message. Returns nullopt if MAC fails.
        // Input format: [Encrypted(PAYLOAD + TYPE_BYTE)] [SESSION_TAG 4 bytes BE] [PIVOT_ID 16 bytes]
        std::optional<std::vector<std::byte>> decrypt(
            std::span<const std::byte> ciphertext,
            const sr::crypto::Nonce& nonce) const;

        bool is_established() const { return _established; }
        const SessionTag& tag() const { return _tag; }
        const PivotID& pivot_id() const { return _pivot_id; }
        const sr::crypto::SessionKeys& keys() const { return _keys; }

        // Build from derived keys (after handshake completes)
        static Session from_keys(const sr::crypto::SessionKeys& keys, const SessionTag& tag, const PivotID& pivot = {});

      private:
        sr::crypto::SessionKeys _keys;
        SessionTag _tag{};
        PivotID _pivot_id{};
        bool _established = false;
        mutable std::atomic<uint64_t> _nonce_counter{0};
    };

    // Session handshake messages — BT-encoded with sealed box.
    //
    // SessionInit outer: BT dict {"":"i", "B":<sealed>}
    // SessionInit inner: BT dict {"I":pubkey, "M":mlkem, "X":x25519, "p":pivot_hopid, "t":tag, "~":sig}
    //
    // SessionAccept outer: BT dict {"":"a", "B":<sealed>}
    // SessionAccept inner: BT dict {"Y":x25519, "c":mlkem_ct, "t":tag, "~":sig}

    struct SessionInit
    {
        sr::crypto::Ed25519PubKey identity;    // "I" — initiator Ed25519 pubkey
        sr::crypto::X25519PubKey x_pubkey;     // "X" — ephemeral X25519 pubkey
        sr::crypto::MLKEMPubKey mlkem_pubkey;  // "M" — ephemeral ML-KEM-768 pubkey
        sr::crypto::Signature signature;       // "~" — Ed25519 signature
        SessionTag tag;                        // "t" — session tag (initiator's inbound)
        PivotID pivot_id;                      // "p" — pivot HopID

        // Serialize to BT outer envelope: {"":"i", "B":<sealed_inner>}
        std::vector<std::byte> seal_for(
            const sr::crypto::Ed25519PubKey& recipient, const sr::crypto::Ed25519SecKey& our_sk) const;

        // Unseal outer envelope and parse inner BT dict
        static std::optional<SessionInit> unseal(
            std::span<const std::byte> bt_outer,
            const sr::crypto::Ed25519PubKey& our_pk,
            const sr::crypto::Ed25519SecKey& our_sk);
    };

    struct SessionAccept
    {
        sr::crypto::X25519PubKey x_pubkey;          // "Y" — receiver's ephemeral X25519
        sr::crypto::MLKEMCiphertext mlkem_ciphertext;  // "c" — ML-KEM-768 ciphertext
        sr::crypto::Signature signature;             // "~" — Ed25519 signature
        SessionTag tag;                              // "t" — recipient session tag

        std::vector<std::byte> seal_for(
            const sr::crypto::Ed25519PubKey& recipient, const sr::crypto::Ed25519SecKey& our_sk) const;

        static std::optional<SessionAccept> unseal(
            std::span<const std::byte> bt_outer,
            const sr::crypto::Ed25519PubKey& our_pk,
            const sr::crypto::Ed25519SecKey& our_sk);
    };

    // Session control message: BT dict {"e":"<method>", "p":<body>}
    // Encrypted with xchacha20-poly1305 session keys.
    struct SessionControl
    {
        std::string method;             // "e" — method name
        std::vector<std::byte> payload; // "p" — method-specific body

        // Serialize to BT dict
        std::vector<std::byte> to_bt() const;

        // Parse from BT dict
        static std::optional<SessionControl> from_bt(std::span<const std::byte> data);
    };

}  // namespace sr::session
