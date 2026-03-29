#pragma once

#include <sr/crypto/types.hpp>

namespace sr::crypto {

// Ed25519 Diffie-Hellman key exchange with BLAKE2b domain separation.
// Matches upstream: hash(nonce, client_pk || server_pk || dh_result)
//
// CONSTRAINT: Both sides MUST agree on who is client and who is server.
// The hash input is always (client_pk || server_pk) regardless of who calls.

SharedSecret dh(
    const Ed25519PubKey& client_pk,
    const Ed25519PubKey& server_pk,
    const Ed25519SecKey& our_sk,
    const Ed25519PubKey& their_pk,
    const Nonce& nonce);

// XOR nonce derivation for onion layers.
// Each hop derives a unique xor_nonce from its shared_secret.
XorNonce derive_xor_nonce(const SharedSecret& shared);

// Short hash for bucket hashing and other uses.
Bytes<SHORT_HASH_SIZE> short_hash(std::span<const std::byte> data);

// Generic BLAKE2b hash
Bytes<HASH_SIZE> blake2b(
    std::span<const std::byte> data,
    std::span<const std::byte> key = {});

}  // namespace sr::crypto
