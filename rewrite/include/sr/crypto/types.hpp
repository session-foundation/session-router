#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

#include <sodium.h>

namespace sr::crypto {

// Fixed-size byte arrays for crypto types
template <size_t N>
using Bytes = std::array<std::byte, N>;

// Key sizes from libsodium
inline constexpr size_t ED25519_PK_SIZE = crypto_sign_PUBLICKEYBYTES;    // 32
inline constexpr size_t ED25519_SK_SIZE = crypto_sign_SECRETKEYBYTES;    // 64
inline constexpr size_t X25519_PK_SIZE = crypto_scalarmult_BYTES;        // 32
inline constexpr size_t X25519_SK_SIZE = crypto_scalarmult_SCALARBYTES;  // 32
inline constexpr size_t SIGNATURE_SIZE = crypto_sign_BYTES;              // 64

// AEAD sizes
inline constexpr size_t AEAD_KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;     // 32
inline constexpr size_t AEAD_NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // 24
inline constexpr size_t AEAD_TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;       // 16

// Sealed box overhead
inline constexpr size_t SEAL_OVERHEAD = crypto_box_SEALBYTES;  // 48

// Short hash for nonce derivation
inline constexpr size_t SHORT_HASH_SIZE = crypto_shorthash_BYTES;  // 8
inline constexpr size_t HASH_SIZE = crypto_generichash_BYTES;      // 32

// Key types
struct Ed25519PubKey : Bytes<ED25519_PK_SIZE> {};
struct Ed25519SecKey : Bytes<ED25519_SK_SIZE> {};
struct X25519PubKey : Bytes<X25519_PK_SIZE> {};
struct X25519SecKey : Bytes<X25519_SK_SIZE> {};
struct Signature : Bytes<SIGNATURE_SIZE> {};
struct SharedSecret : Bytes<HASH_SIZE> {};
struct SymmetricKey : Bytes<AEAD_KEY_SIZE> {};
struct Nonce : Bytes<AEAD_NONCE_SIZE> {};
struct XorNonce : Bytes<AEAD_NONCE_SIZE> {};

// Ed25519 keypair
struct Ed25519KeyPair {
    Ed25519PubKey pk;
    Ed25519SecKey sk;

    static Ed25519KeyPair generate();
};

// X25519 keypair
struct X25519KeyPair {
    X25519PubKey pk;
    X25519SecKey sk;

    static X25519KeyPair generate();
    static X25519KeyPair from_ed25519(const Ed25519KeyPair& ed);
};

// Utility
void sodium_init_once();

inline const std::byte* as_bytes(const auto& arr) {
    return reinterpret_cast<const std::byte*>(arr.data());
}

inline std::byte* as_bytes(auto& arr) {
    return reinterpret_cast<std::byte*>(arr.data());
}

inline const unsigned char* as_uchar(const auto& arr) {
    return reinterpret_cast<const unsigned char*>(arr.data());
}

inline unsigned char* as_uchar(auto& arr) {
    return reinterpret_cast<unsigned char*>(arr.data());
}

}  // namespace sr::crypto
