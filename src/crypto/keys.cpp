#include "keys.hpp"

#include "crypto.hpp"
#include "crypto/session_keys.hpp"
#include "util/bspan.hpp"
#include "util/logging.hpp"

#include <sodium/crypto_box_curve25519xchacha20poly1305.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

namespace srouter
{

    static auto logcat = log::Cat("keys");

    bool PubKey::from_hex(const std::string& str)
    {
        if (str.size() != 2 * size())
            return false;
        oxenc::from_hex(str.begin(), str.end(), begin());
        return true;
    }

    std::string PubKey::to_string() const { return oxenc::to_base32z(begin(), end()); }

    bool PubKey::verify(std::span<const std::byte> message, SignatureView signature) const
    {
        return crypto_sign_verify_detached(
                   as_uspan(signature.sig_data).data(), as_uspan(message).data(), message.size(), udata())
            == 0;
    }

    Ed25519SecretKey Ed25519SecretKey::generate()
    {
        Ed25519SecretKey ret{};
        PubKey pk;
        [[maybe_unused]] int result = crypto_sign_ed25519_keypair(pk.udata(), ret.udata());
        assert(result != -1);
        return ret;
    }

    bool Ed25519SecretKey::check_pubkey() const
    {
        PubKey pk;
        Ed25519SecretKey sk;
        crypto_sign_seed_keypair(pk.udata(), sk.udata(), udata());
        return 0 == sodium_memcmp(pk.data(), pubkey_span().data(), 32);
    }

    void Ed25519SecretKey::recalculate()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        std::array<unsigned char, 32> pk;
        std::array<unsigned char, 64> sk;
        crypto_sign_seed_keypair(pk.data(), sk.data(), udata());
        std::memcpy(data() + 32, pk.data(), 32);
    }

    void Ed25519SecretKey::sign(std::span<std::byte, Signature::size()> sig, std::span<const std::byte> buf) const
    {
        crypto_sign_detached(as_uspan(sig).data(), nullptr, as_uspan(buf).data(), buf.size(), udata());
    }

    Signature Ed25519SecretKey::sign(std::span<const std::byte> buf) const
    {
        Signature sig;
        sign(sig, buf);
        return sig;
    }

    void Ed25519BlindedKey::sign(std::span<std::byte, Signature::size()> sig, std::span<const std::byte> buf) const
    {
        auto ubuf = as_uspan(buf);

        // r = H(s || M) where here s is pseudorandom bytes, generated under standard Ed25519 as
        // part of hashing the seed (i.e. [a,s] = H(k), ignoring `a` clamping).  For blinded keys,
        // however, we instead use `s` created at construction of the BlindedKey object (which is a
        // domain-keyed blake2b hash of the root seed, rather than the second half of a SHA512 of
        // the root key).
        cleared_uc64 nonce;
        crypto_hash_sha512_state hs;
        crypto_hash_sha512_init(&hs);
        crypto_hash_sha512_update(&hs, hash_data.udata(), hash_data.size());
        crypto_hash_sha512_update(&hs, ubuf.data(), ubuf.size());
        crypto_hash_sha512_final(&hs, nonce.data());
        crypto_core_ed25519_scalar_reduce(nonce.data(), nonce.data());

        // Final signature consists of R || S:
        auto R = as_uspan(sig.first<32>());
        auto S = as_uspan(sig.last<32>());

        // R = r * G, store directly into sig to make: sig = (R || uninitialized)
        crypto_scalarmult_ed25519_base_noclamp(R.data(), nonce.data());

        // hram = H(R || A || M)
        unsigned char hram[64];
        crypto_hash_sha512_init(&hs);
        crypto_hash_sha512_update(&hs, R.data(), 32);
        crypto_hash_sha512_update(&hs, pubkey.udata(), 32);
        crypto_hash_sha512_update(&hs, ubuf.data(), ubuf.size());
        crypto_hash_sha512_final(&hs, hram);

        // S = r + H(R || A || M) * a, and we store S directly into sig:
        crypto_core_ed25519_scalar_reduce(hram, hram);
        unsigned char mulres[32];
        crypto_core_ed25519_scalar_mul(mulres, hram, scalar.udata());
        crypto_core_ed25519_scalar_add(S.data(), mulres, nonce.data());
    }

    Signature Ed25519BlindedKey::sign(std::span<const std::byte> buf) const
    {
        Signature sig;
        sign(sig, buf);
        return sig;
    }

    Ed25519BlindedKey::Ed25519BlindedKey(std::span<const std::byte, 32> sc, std::span<const std::byte, 32> hd)
        : scalar{sc}, hash_data{hd}
    {
        crypto_scalarmult_ed25519_base_noclamp(pubkey.udata(), scalar.udata());
    }

    Ed25519BlindedKey::Ed25519BlindedKey(const Ed25519SecretKey& root, std::string_view blind_domain)
    {
        // This function's name is a bit misleading: what it actually does is convert the seed to the
        // Ed25519 private scalar, because that's the operation you do when converting Ed -> X (i.e.
        // an X secret key *is* a private scalar, unlike Ed keys).  We don't care at all about X,
        // but we do want the private scalar and this gives us exactly that.
        //
        // a = clamp(SHA512(seed)[0:32])
        crypto_sign_ed25519_sk_to_curve25519(scalar.udata(), root.udata());

        // f = blinding factor
        auto bfactor = crypto::blinding_scalar(root.pubkey_span(), blind_domain);

        // b = af
        crypto_core_ed25519_scalar_mul(scalar.udata(), scalar.udata(), bfactor.data());

        // Now compute the pubkey from the scalar b:
        // B = bG
        if (0 != crypto_scalarmult_ed25519_base_noclamp(pubkey.udata(), scalar.udata()))
            throw std::runtime_error{"Keypair blinding failed!"};

        // In regular Ed25519, the hash data (used during signing) is derived from the hash of seed
        // (i.e. the second half of the SHA512 operation above).  It seems preferable, however, to
        // not use identical hash data for a subkey, so instead we do our own keyed hash of the seed
        // to get some equivalent (but different valued) hash data for the same purpose.
        crypto_generichash_blake2b(
            hash_data.udata(),
            hash_data.size(),
            reinterpret_cast<const unsigned char*>(root.data()),
            32,
            reinterpret_cast<const unsigned char*>(blind_domain.data()),
            blind_domain.size());
    }

    std::vector<std::byte> PubKey::seal_box(std::span<const std::byte> message) const
    {
        std::vector<std::byte> ciphertext;
        ciphertext.resize(message.size() + crypto_box_curve25519xchacha20poly1305_SEALBYTES);

        X25519PubKey xpk{*this};

        if (0
            != crypto_box_curve25519xchacha20poly1305_seal(
                reinterpret_cast<unsigned char*>(ciphertext.data()),
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size(),
                xpk.udata()))
            throw std::runtime_error{"Sealed box encryption failed!"};

        return ciphertext;
    }

    std::vector<std::byte> Ed25519SecretKey::unseal_box(std::span<const std::byte> ciphertext) const
    {
        if (ciphertext.size() < crypto_box_curve25519xchacha20poly1305_SEALBYTES)
            throw std::runtime_error{"Decryption failed: ciphertext too short"};

        X25519KeyPair x{*this};

        std::vector<std::byte> message;
        message.resize(ciphertext.size() - crypto_box_curve25519xchacha20poly1305_SEALBYTES);

        if (0
            != crypto_box_curve25519xchacha20poly1305_seal_open(
                reinterpret_cast<unsigned char*>(message.data()),
                reinterpret_cast<const unsigned char*>(ciphertext.data()),
                ciphertext.size(),
                x.pub.udata(),
                x.sec.udata()))
            throw std::runtime_error{"Sealed box decryption failed!"};

        return message;
    }

    SymmNonce SymmNonce::make_random()
    {
        SymmNonce n;
        randombytes_buf(n.data(), n.size());
        return n;
    }

}  // namespace srouter
