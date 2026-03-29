#pragma once

#include <optional>
#include <span>
#include <vector>

#include <sr/crypto/types.hpp>

namespace sr::crypto {

// Sealed box encryption: encrypt to an Ed25519 pubkey without needing
// the recipient's agreement. Used for session init handshake.
// Internally converts Ed25519 → X25519 for the box operation.

std::vector<std::byte> seal(
    std::span<const std::byte> plaintext,
    const Ed25519PubKey& recipient_pk);

// Unseal with Ed25519 secret key.
// Returns nullopt if decryption fails (wrong key, tampered, truncated).
std::optional<std::vector<std::byte>> unseal(
    std::span<const std::byte> ciphertext,
    const Ed25519PubKey& our_pk,
    const Ed25519SecKey& our_sk);

}  // namespace sr::crypto
