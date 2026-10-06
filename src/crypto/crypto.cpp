#include "crypto.hpp"

#include "crypto/keys.hpp"
#include "util/bspan.hpp"
#include "util/logging.hpp"
#include "util/random.hpp"

#include <oxenc/endian.h>
#include <sodium/core.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_stream_xchacha20.h>
#include <sodium/utils.h>

#include <cassert>
#include <cstring>
#include <stdexcept>
#ifdef SROUTER_HAVE_CRYPT
#include <crypt.h>
#endif

namespace srouter::crypto
{
    static auto logcat = log::Cat("crypto");

    static_assert(TAG_SIZE == crypto_aead_xchacha20poly1305_ietf_ABYTES);
    static_assert(SymmNonce::SIZE == crypto_stream_xchacha20_NONCEBYTES);
    static_assert(SymmKey::SIZE == crypto_stream_xchacha20_KEYBYTES);

    static bool dh(
        SymmKey& out,
        const PubKey& client_pk,
        const PubKey& server_pk,
        bool we_are_client,
        const Ed25519SecretKey& local_keys,
        const SymmNonce& nonce)
    {
        SymmKey shared;

        // Somewhat misnamed: actually gets the private scalar (which happens to be what you need
        // for converting to X):
        std::array<unsigned char, 32> a;
        crypto_sign_ed25519_sk_to_curve25519(a.data(), local_keys.udata());

        if (crypto_scalarmult_ed25519(shared.udata(), a.data(), (we_are_client ? server_pk : client_pk).udata()))
            return false;

        crypto_generichash_blake2b_state h;
        crypto_generichash_blake2b_init(&h, nonce.udata(), nonce.size(), shared.size());
        crypto_generichash_blake2b_update(&h, client_pk.udata(), client_pk.size());
        crypto_generichash_blake2b_update(&h, server_pk.udata(), server_pk.size());
        crypto_generichash_blake2b_update(&h, shared.udata(), shared.size());
        crypto_generichash_blake2b_final(&h, out.udata(), out.size());
        return true;
    }

    std::optional<NetworkAddress> maybe_decrypt_name(
        std::string_view ciphertext, const SymmNonce& nonce, std::string_view namestr)
    {
        const auto payloadsize = ciphertext.size() - TAG_SIZE;
        if (payloadsize != 32)
            return std::nullopt;

        auto bname = as_bspan(namestr);

        // The (unkeyed) blake2b hash of the name is the (public) SNS storage key:
        auto namehash = shorthash(bname);

        // The value itself is encrypted with a symmetric key that is also a blake2b hash of the
        // name, but using a hash key to make it unrelated to the public hash:
        AlignedBuffer<32> derivedKey;
        crypto_generichash_blake2b(
            derivedKey.udata(),
            derivedKey.size(),
            as_uspan(bname).data(),
            bname.size(),
            namehash.udata(),
            namehash.size());

        auto result = std::make_optional<NetworkAddress>();
        result->is_client = true;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                result->pubkey.udata(),
                nullptr,
                nullptr,
                reinterpret_cast<const uint8_t*>(ciphertext.data()),
                ciphertext.size(),
                nullptr,
                0,
                nonce.udata(),
                derivedKey.udata())
            != 0)
            return std::nullopt;

        return result;
    }

    void xchacha20(std::span<std::byte> buf, const SymmKey& secret, const SymmNonce& nonce)
    {
        auto* d = reinterpret_cast<unsigned char*>(buf.data());
        crypto_stream_xchacha20_xor(d, d, buf.size(), nonce.udata(), secret.udata());
    }

    void xchacha20_poly1305_encrypt_inplace(std::span<std::byte> buf, const SymmKey& secret, const SymmNonce& nonce)
    {
        assert(buf.size() >= TAG_SIZE);
        auto payload_size = buf.size() - TAG_SIZE;
        auto* buf_cptr = reinterpret_cast<unsigned char*>(buf.data());
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            buf_cptr, nullptr, buf_cptr, payload_size, nullptr, 0, nullptr, nonce.udata(), secret.udata());
    }

    void xchacha20_poly1305_encrypt_inplace(std::string& buf, const SymmKey& secret, const SymmNonce& nonce)
    {
        xchacha20_poly1305_encrypt_inplace(
            std::span<std::byte>{reinterpret_cast<std::byte*>(buf.data()), buf.size()}, secret, nonce);
    }

    std::optional<std::span<std::byte>> xchacha20_poly1305_decrypt_inplace(
        std::span<std::byte> buf, const SymmKey& secret, const SymmNonce& nonce)
    {
        if (buf.size() < TAG_SIZE)
        {
            log::warning(
                logcat, "Unable to decrypt: payload size {} is too small to be valid (< {})!", buf.size(), TAG_SIZE);
            return std::nullopt;
        }
        auto* buf_cptr = reinterpret_cast<unsigned char*>(buf.data());
        unsigned long long payload_size{0};
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                buf_cptr, &payload_size, nullptr, buf_cptr, buf.size(), nullptr, 0, nonce.udata(), secret.udata())
            != 0)
        {
            log::warning(logcat, "Decryption of {}B ciphertext failed", buf.size());
            return std::nullopt;
        }
        assert(payload_size == buf.size() - TAG_SIZE);
        return buf.first(payload_size);
    }

    std::vector<std::byte> xchacha20_poly1305_encrypt(
        std::span<const std::byte> plaintext, const SymmKey& secret, const SymmNonce& nonce)
    {
        std::vector<std::byte> ciphertext;
        ciphertext.resize(plaintext.size() + TAG_SIZE);
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            reinterpret_cast<unsigned char*>(ciphertext.data()),
            nullptr,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            plaintext.size(),
            nullptr,
            0,
            nullptr,
            nonce.udata(),
            secret.udata());
        return ciphertext;
    }

    std::optional<std::vector<std::byte>> xchacha20_poly1305_decrypt(
        std::span<const std::byte> ciphertext, const SymmKey& secret, const SymmNonce& nonce)
    {
        auto result = std::make_optional<std::vector<std::byte>>();
        if (ciphertext.size() < TAG_SIZE)
        {
            result.reset();
            return result;
        }
        auto& plaintext = *result;
        plaintext.resize(ciphertext.size() - TAG_SIZE);
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                reinterpret_cast<unsigned char*>(plaintext.data()),
                nullptr,
                nullptr,
                reinterpret_cast<const unsigned char*>(ciphertext.data()),
                ciphertext.size(),
                nullptr,
                0,
                nonce.udata(),
                secret.udata())
            != 0)
        {
            log::warning(logcat, "Decryption failed");
            result.reset();
        }

        return result;
    }

    bool dh_client(SymmKey& shared, const PubKey& pk, const Ed25519SecretKey& sk, const SymmNonce& n)
    {
        if (dh(shared, sk.to_pubkey(), pk, true, sk, n))
            return true;

        log::warning(logcat, "dh_client - dh failed");
        return false;
    }

    // Deprecated
    std::tuple<SymmKey, PubKey, SymmNonce> dh_client_gen(const PubKey& server_pk)
    {
        std::tuple<SymmKey, PubKey, SymmNonce> result;
        auto& [secret, eph_pk, nonce] = result;

        auto eph_keys = Ed25519SecretKey::generate();
        nonce = SymmNonce::make_random();
        if (!dh_client(secret, server_pk, eph_keys, nonce))
            throw std::invalid_argument{"shared secret generation failed: remote pubkey is not a valid Ed25519 pubkey"};
        eph_pk.assign(eph_keys.pubkey_span());
        return result;
    }

    /// path dh relay side
    bool dh_server(SymmKey& shared, const PubKey& pk, const Ed25519SecretKey& sk, const SymmNonce& n)
    {
        if (dh(shared, pk, sk.to_pubkey(), false, sk, n))
            return true;

        log::warning(logcat, "dh_server - dh failed");
        return false;
    }

    void shorthash(std::span<std::byte, 32> result, std::span<const std::byte> buf)
    {
        crypto_generichash_blake2b(
            reinterpret_cast<unsigned char*>(result.data()),
            result.size(),
            reinterpret_cast<const unsigned char*>(buf.data()),
            buf.size(),
            nullptr,
            0);
    }
    AlignedBuffer<32> shorthash(std::span<const std::byte> buf)
    {
        AlignedBuffer<32> result;
        shorthash(result, buf);
        return result;
    }

    std::array<unsigned char, 32> blinding_scalar(std::span<const std::byte, 32> pubkey, std::string_view blind_domain)
    {
        if (blind_domain.size() > crypto_generichash_KEYBYTES_MAX)
            blind_domain = blind_domain.substr(0, crypto_generichash_KEYBYTES_MAX);

        // n = H(pk, key=blind_domain)
        std::array<unsigned char, 64> n;
        crypto_generichash_blake2b(
            n.data(),
            n.size(),
            reinterpret_cast<const unsigned char*>(pubkey.data()),
            pubkey.size(),
            reinterpret_cast<const unsigned char*>(blind_domain.data()),
            blind_domain.size());

        // out = scalar_reduce(n)
        std::array<unsigned char, 32> out;
        crypto_core_ed25519_scalar_reduce(out.data(), n.data());

        return out;
    }

    bool blind(PubKey& blinded, const PubKey& root, std::string_view blind_domain)
    {
        return 0
            == crypto_scalarmult_ed25519_noclamp(
                   blinded.udata(), blinding_scalar(root, blind_domain).data(), root.udata());
    }

#ifdef SROUTER_HAVE_CRYPT
    bool check_passwd_hash(std::string pwhash, std::string challenge)
    {
        bool ret = false;
        auto pos = pwhash.find_last_of('$');
        auto settings = pwhash.substr(0, pos);
        crypt_data data{};
        if (char* ptr = crypt_r(challenge.c_str(), settings.c_str(), &data))
        {
            ret = ptr == pwhash;
        }
        sodium_memzero(&data, sizeof(data));
        return ret;
    }
#endif

}  // namespace srouter::crypto

namespace srouter
{
    // Called during static initialization to initialize libsodium.  (The CSRNG return is
    // not useful, but just here to get this called during static initialization of `csrng`).
    static CSRNG _initialize_crypto()
    {
        if (sodium_init() == -1)
        {
            log::critical(crypto::logcat, "sodium_init() failed, unable to continue!");
            std::abort();
        }

        return CSRNG{};
    }

    CSRNG csrng = _initialize_crypto();

}  // namespace srouter
