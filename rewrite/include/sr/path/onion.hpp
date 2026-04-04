#pragma once

#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/types.hpp>
#include <sr/path/hop.hpp>

#include <span>
#include <vector>

namespace sr::path
{

    // Onion construction for path building.
    // CONSTRAINT: frames encrypted in reverse (pivot to edge).
    // CONSTRAINT: frame rotation at each relay (asymmetric onion/de-onion).

    inline constexpr size_t BUILD_FRAME_SIZE = 169;
    inline constexpr size_t BUILD_LENGTH = 8;  // max hops (4 real + 4 dummy)
    inline constexpr size_t BUILD_MSG_SIZE = BUILD_FRAME_SIZE * BUILD_LENGTH;

    // Path message framing: trailer appended to every path message.
    // [nonce (24 bytes)] [hopid (16 bytes)] [msgtype (1 byte)]
    inline constexpr size_t PATH_TRAILER_SIZE = 24 + 16 + 1;  // 41 bytes

    // Message types for path framing
    inline constexpr uint8_t PATH_MSG_DATA_OR_CONTROL = 0x01;
    inline constexpr uint8_t PATH_MSG_SESSION_HANDSHAKE = 0x02;

    // Build the onion-encrypted path build message.
    struct PathBuildResult
    {
        std::array<std::byte, BUILD_MSG_SIZE> frames;
        std::vector<Hop> hops;  // populated with shared_secret and xor_nonce
    };

    PathBuildResult build_onion(
        const std::vector<sr::contact::RelayContact>& relays,
        const sr::crypto::Ed25519KeyPair& ephemeral_keys,
        std::chrono::seconds lifetime);

    // Decrypt a single build frame as a relay.
    struct DecryptedFrame
    {
        HopID rxid;
        HopID txid;
        sr::contact::RouterID upstream;
        std::chrono::seconds lifetime;
        sr::crypto::SharedSecret shared_secret;
        sr::crypto::XorNonce xor_nonce;
    };

    std::optional<DecryptedFrame> decrypt_build_frame(
        std::span<const std::byte> frame,
        const sr::crypto::Ed25519SecKey& our_sk,
        const sr::crypto::Ed25519PubKey& our_pk);

    // === Path message framing ===

    // Append path trailer: [nonce 24B] [hopid 16B] [msgtype 1B]
    std::vector<std::byte> append_path_trailer(
        std::span<const std::byte> payload,
        const sr::crypto::Nonce& nonce,
        const HopID& hopid,
        uint8_t msgtype);

    // Strip path trailer from the end of a message.
    // Returns the payload and populates the nonce, hopid, msgtype outputs.
    // Returns nullopt if message is too short.
    struct PathTrailer
    {
        sr::crypto::Nonce nonce;
        HopID hopid;
        uint8_t msgtype;
    };

    std::optional<PathTrailer> strip_path_trailer(
        std::span<const std::byte> msg,
        std::span<std::byte>& payload_out);

}  // namespace sr::path
