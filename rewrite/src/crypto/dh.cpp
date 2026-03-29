#include <sr/crypto/dh.hpp>

#include <cstring>
#include <sodium.h>

namespace sr::crypto {

SharedSecret dh(
    const Ed25519PubKey& client_pk,
    const Ed25519PubKey& server_pk,
    const Ed25519SecKey& our_sk,
    const Ed25519PubKey& their_pk,
    const Nonce& nonce)
{
    // Convert Ed25519 keys to X25519 for scalar multiplication
    unsigned char x_sk[crypto_scalarmult_SCALARBYTES];
    unsigned char x_pk[crypto_scalarmult_BYTES];
    unsigned char dh_result[crypto_scalarmult_BYTES];

    if (crypto_sign_ed25519_sk_to_curve25519(x_sk, as_uchar(our_sk)) != 0)
        throw std::runtime_error("DH: Ed25519 → X25519 secret key conversion failed");

    if (crypto_sign_ed25519_pk_to_curve25519(x_pk, as_uchar(their_pk)) != 0)
        throw std::runtime_error("DH: Ed25519 → X25519 public key conversion failed");

    if (crypto_scalarmult(dh_result, x_sk, x_pk) != 0)
        throw std::runtime_error("DH: scalar multiplication failed");

    // BLAKE2b(nonce as key, client_pk || server_pk || dh_result)
    // CONSTRAINT: ordering is ALWAYS (client_pk || server_pk), regardless of who we are
    SharedSecret shared;
    crypto_generichash_state state;
    crypto_generichash_init(
        &state,
        as_uchar(nonce), nonce.size(),
        HASH_SIZE);
    crypto_generichash_update(&state, as_uchar(client_pk), client_pk.size());
    crypto_generichash_update(&state, as_uchar(server_pk), server_pk.size());
    crypto_generichash_update(&state, dh_result, sizeof(dh_result));
    crypto_generichash_final(&state, as_uchar(shared), HASH_SIZE);

    sodium_memzero(x_sk, sizeof(x_sk));
    sodium_memzero(dh_result, sizeof(dh_result));

    return shared;
}

XorNonce derive_xor_nonce(const SharedSecret& shared) {
    XorNonce xn{};
    // Short hash of shared secret, zero-padded to nonce size
    unsigned char sh[SHORT_HASH_SIZE];
    // Use a zero key for shorthash
    unsigned char key[crypto_shorthash_KEYBYTES] = {};
    crypto_shorthash(sh, as_uchar(shared), shared.size(), key);
    std::memcpy(xn.data(), sh, SHORT_HASH_SIZE);
    return xn;
}

Bytes<SHORT_HASH_SIZE> short_hash(std::span<const std::byte> data) {
    Bytes<SHORT_HASH_SIZE> out;
    unsigned char key[crypto_shorthash_KEYBYTES] = {};
    crypto_shorthash(
        as_uchar(out),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(),
        key);
    return out;
}

Bytes<HASH_SIZE> blake2b(
    std::span<const std::byte> data,
    std::span<const std::byte> key)
{
    Bytes<HASH_SIZE> out;
    crypto_generichash(
        as_uchar(out), HASH_SIZE,
        reinterpret_cast<const unsigned char*>(data.data()), data.size(),
        key.empty() ? nullptr : reinterpret_cast<const unsigned char*>(key.data()),
        key.size());
    return out;
}

}  // namespace sr::crypto
