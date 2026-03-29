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

    // Build the onion-encrypted path build message.
    // hops: the relay contacts for each hop in the path (edge to pivot order).
    // our_sk: our Ed25519 secret key for DH with each hop.
    // Returns the encrypted frames and populates hop_secrets with shared secrets.
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
    // Returns the decrypted payload (rxid, txid, upstream, lifetime).
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

}  // namespace sr::path
