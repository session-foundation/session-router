#include <sr/crypto/session_keys.hpp>

#include <cstring>
#include <sodium.h>

namespace sr::crypto {

SessionKeys derive_session_keys(
    const X25519PubKey& initiator_x_pk,
    const X25519PubKey& receiver_x_pk,
    const X25519SecKey& our_x_sk,
    const X25519PubKey& their_x_pk,
    bool is_initiator,
    std::span<const std::byte> mlkem_shared_secret,
    std::span<const std::byte> mlkem_pk,
    const Ed25519PubKey& initiator_rid,
    const Ed25519PubKey& receiver_rid)
{
    // X25519 DH
    unsigned char dh_result[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(dh_result, as_uchar(our_x_sk), as_uchar(their_x_pk)) != 0)
        throw std::runtime_error("session_keys: X25519 scalar multiplication failed");

    // Compute 64-byte hash:
    // BLAKE2b-512(
    //   key = "session-router-session-keys",
    //   X || Y || dh_result || mlkem_ss || mlkem_pk || initiator_rid || receiver_rid
    // )
    // where X = initiator's X25519 pk, Y = receiver's X25519 pk
    static constexpr std::string_view domain = "session-router-session-keys";

    Bytes<64> h;
    crypto_generichash_state state;
    crypto_generichash_init(
        &state,
        reinterpret_cast<const unsigned char*>(domain.data()), domain.size(),
        64);

    // X (always initiator's pubkey)
    crypto_generichash_update(&state, as_uchar(initiator_x_pk), initiator_x_pk.size());
    // Y (always receiver's pubkey)
    crypto_generichash_update(&state, as_uchar(receiver_x_pk), receiver_x_pk.size());
    // DH result
    crypto_generichash_update(&state, dh_result, sizeof(dh_result));
    // ML-KEM shared secret
    crypto_generichash_update(&state,
        reinterpret_cast<const unsigned char*>(mlkem_shared_secret.data()),
        mlkem_shared_secret.size());
    // ML-KEM public key
    crypto_generichash_update(&state,
        reinterpret_cast<const unsigned char*>(mlkem_pk.data()),
        mlkem_pk.size());
    // Initiator RouterID
    crypto_generichash_update(&state, as_uchar(initiator_rid), initiator_rid.size());
    // Receiver RouterID
    crypto_generichash_update(&state, as_uchar(receiver_rid), receiver_rid.size());

    crypto_generichash_final(&state, as_uchar(h), 64);

    sodium_memzero(dh_result, sizeof(dh_result));

    // Split: k1 = first 32 bytes, k2 = last 32 bytes
    // CONSTRAINT: initiator uses (out=k1, in=k2), receiver uses (out=k2, in=k1)
    SessionKeys keys;
    if (is_initiator) {
        std::memcpy(keys.key_out.data(), h.data(), 32);
        std::memcpy(keys.key_in.data(), reinterpret_cast<const std::byte*>(h.data()) + 32, 32);
    } else {
        std::memcpy(keys.key_out.data(), reinterpret_cast<const std::byte*>(h.data()) + 32, 32);
        std::memcpy(keys.key_in.data(), h.data(), 32);
    }

    sodium_memzero(h.data(), h.size());
    return keys;
}

}  // namespace sr::crypto
