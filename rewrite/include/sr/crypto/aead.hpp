#pragma once

#include <optional>
#include <span>
#include <vector>

#include <sr/crypto/types.hpp>

namespace sr::crypto {

// xchacha20-poly1305 AEAD encryption/decryption.
// Used for session data messages and path control messages.

// Encrypt in-place. Appends TAG_SIZE bytes of MAC to the end of the buffer.
// Buffer must have TAG_SIZE extra bytes available.
// Returns span over the ciphertext (input + tag).
std::span<std::byte> aead_encrypt_inplace(
    std::span<std::byte> buf,     // plaintext; must have AEAD_TAG_SIZE extra room
    size_t plaintext_len,
    const SymmetricKey& key,
    const Nonce& nonce);

// Decrypt in-place. Verifies and strips the MAC.
// Returns span over the plaintext, or nullopt if MAC verification fails.
std::optional<std::span<std::byte>> aead_decrypt_inplace(
    std::span<std::byte> buf,     // ciphertext + tag
    const SymmetricKey& key,
    const Nonce& nonce);

// Allocating variants
std::vector<std::byte> aead_encrypt(
    std::span<const std::byte> plaintext,
    const SymmetricKey& key,
    const Nonce& nonce);

std::optional<std::vector<std::byte>> aead_decrypt(
    std::span<const std::byte> ciphertext,  // includes tag
    const SymmetricKey& key,
    const Nonce& nonce);

// Plain xchacha20 stream cipher (no authentication).
// Used for onion layers in path building and data transport.
void xchacha20_inplace(
    std::span<std::byte> buf,
    const SymmetricKey& key,
    const Nonce& nonce);

}  // namespace sr::crypto
