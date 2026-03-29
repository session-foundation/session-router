#include <sr/crypto/sealed_box.hpp>

#include <sodium.h>

namespace sr::crypto {

std::vector<std::byte> seal(
    std::span<const std::byte> plaintext,
    const Ed25519PubKey& recipient_pk)
{
    // Convert Ed25519 pubkey to X25519 for sealed box
    unsigned char x_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(x_pk, as_uchar(recipient_pk)) != 0)
        throw std::runtime_error("seal: Ed25519 → X25519 conversion failed");

    std::vector<std::byte> out(plaintext.size() + SEAL_OVERHEAD);
    if (crypto_box_seal(
            reinterpret_cast<unsigned char*>(out.data()),
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            plaintext.size(),
            x_pk) != 0)
        throw std::runtime_error("seal: encryption failed");

    return out;
}

std::optional<std::vector<std::byte>> unseal(
    std::span<const std::byte> ciphertext,
    const Ed25519PubKey& our_pk,
    const Ed25519SecKey& our_sk)
{
    if (ciphertext.size() < SEAL_OVERHEAD)
        return std::nullopt;

    // Convert Ed25519 keys to X25519
    unsigned char x_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char x_sk[crypto_box_SECRETKEYBYTES];

    if (crypto_sign_ed25519_pk_to_curve25519(x_pk, as_uchar(our_pk)) != 0)
        return std::nullopt;
    if (crypto_sign_ed25519_sk_to_curve25519(x_sk, as_uchar(our_sk)) != 0) {
        sodium_memzero(x_sk, sizeof(x_sk));
        return std::nullopt;
    }

    std::vector<std::byte> out(ciphertext.size() - SEAL_OVERHEAD);
    int rc = crypto_box_seal_open(
        reinterpret_cast<unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(ciphertext.data()),
        ciphertext.size(),
        x_pk, x_sk);

    sodium_memzero(x_sk, sizeof(x_sk));

    if (rc != 0)
        return std::nullopt;

    return out;
}

}  // namespace sr::crypto
