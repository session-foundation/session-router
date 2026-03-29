#include <sr/crypto/blind.hpp>

#include <cstring>
#include <sodium.h>

namespace sr::crypto {

// Compute blinding scalar: H(pubkey, key=domain) reduced mod L
static Bytes<32> blinding_scalar(
    const Ed25519PubKey& pk,
    std::string_view domain)
{
    Bytes<64> h64;
    crypto_generichash(
        as_uchar(h64), 64,
        as_uchar(pk), pk.size(),
        reinterpret_cast<const unsigned char*>(domain.data()), domain.size());

    Bytes<32> scalar;
    crypto_core_ed25519_scalar_reduce(as_uchar(scalar), as_uchar(h64));
    return scalar;
}

Ed25519PubKey blind_pubkey(
    const Ed25519PubKey& root_pk,
    std::string_view domain)
{
    auto scalar = blinding_scalar(root_pk, domain);

    Ed25519PubKey blinded;
    if (crypto_scalarmult_ed25519_noclamp(
            as_uchar(blinded), as_uchar(scalar), as_uchar(root_pk)) != 0)
        throw std::runtime_error("blind_pubkey: scalar multiplication failed");

    return blinded;
}

BlindedKeyPair BlindedKeyPair::from_root(
    const Ed25519SecKey& root_sk,
    const Ed25519PubKey& root_pk,
    std::string_view domain)
{
    BlindedKeyPair bkp;

    auto scalar = blinding_scalar(root_pk, domain);

    // Blinded pubkey = scalar * root_pk
    if (crypto_scalarmult_ed25519_noclamp(
            as_uchar(bkp.pk), as_uchar(scalar), as_uchar(root_pk)) != 0)
        throw std::runtime_error("BlindedKeyPair: scalar multiplication failed");

    // Derive sign_key: scalar * root_sk_scalar (first 32 bytes of sk after clamping)
    // Ed25519 secret key layout: [scalar:32][nonce:32]
    unsigned char root_scalar[32];
    // Hash the seed to get the actual scalar (Ed25519 convention)
    unsigned char h[64];
    crypto_hash_sha512(h, as_uchar(root_sk), 32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    std::memcpy(root_scalar, h, 32);

    // blinded_scalar = scalar * root_scalar mod L
    unsigned char blinded_scalar[32];
    crypto_core_ed25519_scalar_mul(blinded_scalar, as_uchar(scalar), root_scalar);

    // sign_key = [blinded_scalar:32][blinded_pk:32]
    std::memcpy(bkp.sign_key.data(), blinded_scalar, 32);
    std::memcpy(reinterpret_cast<unsigned char*>(bkp.sign_key.data()) + 32,
                as_uchar(bkp.pk), 32);

    // hash_data = blake2b(root_sk_seed, key=domain)
    // Used as the nonce component in the Ed25519 signing
    crypto_generichash(
        as_uchar(bkp.hash_data), 32,
        as_uchar(root_sk), 32,  // just the seed portion
        reinterpret_cast<const unsigned char*>(domain.data()), domain.size());

    sodium_memzero(root_scalar, sizeof(root_scalar));
    sodium_memzero(h, sizeof(h));
    sodium_memzero(blinded_scalar, sizeof(blinded_scalar));

    return bkp;
}

Signature BlindedKeyPair::sign(std::span<const std::byte> message) const {
    // Ed25519 signing with modified nonce derivation:
    // nonce = H(hash_data || message) (instead of H(secret_nonce || message))
    // R = nonce * B
    // S = nonce + H(R || pk || message) * blinded_scalar

    unsigned char nonce_hash[64];
    crypto_hash_sha512_state nh_state;
    crypto_hash_sha512_init(&nh_state);
    crypto_hash_sha512_update(&nh_state, as_uchar(hash_data), hash_data.size());
    crypto_hash_sha512_update(&nh_state,
        reinterpret_cast<const unsigned char*>(message.data()), message.size());
    crypto_hash_sha512_final(&nh_state, nonce_hash);

    unsigned char nonce_scalar[32];
    crypto_core_ed25519_scalar_reduce(nonce_scalar, nonce_hash);

    // R = nonce_scalar * B (base point)
    unsigned char R[32];
    crypto_scalarmult_ed25519_base_noclamp(R, nonce_scalar);

    // H(R || pk || message)
    unsigned char hram[64];
    crypto_hash_sha512_state hram_state;
    crypto_hash_sha512_init(&hram_state);
    crypto_hash_sha512_update(&hram_state, R, 32);
    crypto_hash_sha512_update(&hram_state, as_uchar(pk), 32);
    crypto_hash_sha512_update(&hram_state,
        reinterpret_cast<const unsigned char*>(message.data()), message.size());
    crypto_hash_sha512_final(&hram_state, hram);

    unsigned char hram_scalar[32];
    crypto_core_ed25519_scalar_reduce(hram_scalar, hram);

    // S = nonce_scalar + hram_scalar * blinded_scalar
    unsigned char S[32];
    unsigned char tmp[32];
    crypto_core_ed25519_scalar_mul(tmp, hram_scalar,
        reinterpret_cast<const unsigned char*>(sign_key.data()));
    crypto_core_ed25519_scalar_add(S, nonce_scalar, tmp);

    Signature sig;
    std::memcpy(sig.data(), R, 32);
    std::memcpy(reinterpret_cast<unsigned char*>(sig.data()) + 32, S, 32);

    sodium_memzero(nonce_hash, sizeof(nonce_hash));
    sodium_memzero(nonce_scalar, sizeof(nonce_scalar));

    return sig;
}

bool blind_verify(
    std::span<const std::byte> message,
    const Signature& sig,
    const Ed25519PubKey& blinded_pk)
{
    return crypto_sign_verify_detached(
        as_uchar(sig),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size(),
        as_uchar(blinded_pk)) == 0;
}

}  // namespace sr::crypto
