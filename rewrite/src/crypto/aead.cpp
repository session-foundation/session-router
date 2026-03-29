#include <sr/crypto/aead.hpp>

#include <cstring>
#include <sodium.h>

namespace sr::crypto {

std::span<std::byte> aead_encrypt_inplace(
    std::span<std::byte> buf,
    size_t plaintext_len,
    const SymmetricKey& key,
    const Nonce& nonce)
{
    if (buf.size() < plaintext_len + AEAD_TAG_SIZE)
        throw std::runtime_error("aead_encrypt_inplace: buffer too small");

    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(buf.data()),
        &clen,
        reinterpret_cast<const unsigned char*>(buf.data()),
        plaintext_len,
        nullptr, 0,  // no additional data
        nullptr,
        as_uchar(nonce),
        as_uchar(key));

    return buf.subspan(0, clen);
}

std::optional<std::span<std::byte>> aead_decrypt_inplace(
    std::span<std::byte> buf,
    const SymmetricKey& key,
    const Nonce& nonce)
{
    if (buf.size() < AEAD_TAG_SIZE)
        return std::nullopt;

    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(buf.data()),
            &mlen,
            nullptr,
            reinterpret_cast<const unsigned char*>(buf.data()),
            buf.size(),
            nullptr, 0,
            as_uchar(nonce),
            as_uchar(key)) != 0)
        return std::nullopt;

    return buf.subspan(0, mlen);
}

std::vector<std::byte> aead_encrypt(
    std::span<const std::byte> plaintext,
    const SymmetricKey& key,
    const Nonce& nonce)
{
    std::vector<std::byte> out(plaintext.size() + AEAD_TAG_SIZE);
    std::memcpy(out.data(), plaintext.data(), plaintext.size());
    aead_encrypt_inplace(out, plaintext.size(), key, nonce);
    return out;
}

std::optional<std::vector<std::byte>> aead_decrypt(
    std::span<const std::byte> ciphertext,
    const SymmetricKey& key,
    const Nonce& nonce)
{
    if (ciphertext.size() < AEAD_TAG_SIZE)
        return std::nullopt;

    std::vector<std::byte> buf(ciphertext.begin(), ciphertext.end());
    auto result = aead_decrypt_inplace(buf, key, nonce);
    if (!result)
        return std::nullopt;

    buf.resize(result->size());
    return buf;
}

void xchacha20_inplace(
    std::span<std::byte> buf,
    const SymmetricKey& key,
    const Nonce& nonce)
{
    crypto_stream_xchacha20_xor(
        reinterpret_cast<unsigned char*>(buf.data()),
        reinterpret_cast<const unsigned char*>(buf.data()),
        buf.size(),
        as_uchar(nonce),
        as_uchar(key));
}

}  // namespace sr::crypto
