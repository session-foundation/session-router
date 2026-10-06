#include "session_keys.hpp"

#include "util/random.hpp"

#include <mlkem_native.h>
#include <oxenc/endian.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>

#include <span>
#include <utility>

namespace srouter
{
    static_assert(X25519PubKey::size() == crypto_scalarmult_curve25519_BYTES);
    static_assert(X25519PubKey::size() == crypto_kx_PUBLICKEYBYTES);
    static_assert(X25519SecKey::size() == crypto_scalarmult_curve25519_SCALARBYTES);
    static_assert(X25519SecKey::size() == crypto_kx_SECRETKEYBYTES);

    X25519PubKey::X25519PubKey(const PubKey& ed_pk)
    {
        if (0 != crypto_sign_ed25519_pk_to_curve25519(udata(), ed_pk.udata()))
            throw std::runtime_error{"Ed->X25519 conversion failed: invalid Ed25519 pubkey"};
    }

    X25519SecKey::X25519SecKey(const Ed25519SecretKey& ed_sk)
    {
        crypto_sign_ed25519_sk_to_curve25519(udata(), ed_sk.udata());
    }

    X25519PubKey X25519SecKey::to_pubkey() const
    {
        X25519PubKey pk;
        crypto_scalarmult_curve25519_base(pk.udata(), udata());
        return pk;
    }

    X25519PubKey X25519SecKey::operator*(const X25519PubKey& pk) const
    {
        X25519PubKey result;

        if (0 != crypto_scalarmult_curve25519(result.udata(), udata(), pk.udata()))
            throw std::runtime_error{"X25519 scalarmult failed"};

        return result;
    }

    X25519KeyPair::X25519KeyPair(const Ed25519SecretKey& ed_sk) : sec{ed_sk} { pub = sec.to_pubkey(); }

    X25519KeyPair X25519KeyPair::generate()
    {
        X25519KeyPair keys;
        crypto_kx_keypair(keys.pub.udata(), keys.sec.udata());
        return keys;
    }

    // Check that the implicit pointer conversions we do to get the leancrypto primitives are okay.
    // (These aren't exhaustive, but if any of these don't hold something is definitely wrong).
    static_assert(MLKEM768_PUBLICKEYBYTES == sizeof(MLKEM768PubKey));
    static_assert(MLKEM768_PUBLICKEYBYTES == MLKEM768PubKey::size());

    static_assert(MLKEM768_SECRETKEYBYTES == sizeof(MLKEM768SecKey));
    static_assert(MLKEM768_SECRETKEYBYTES == MLKEM768SecKey::size());

    static_assert(MLKEM768_BYTES == sizeof(MLKEMSharedSecret));
    static_assert(MLKEM768_BYTES == MLKEMSharedSecret::size());

    MLKEM768KeyPair MLKEM768KeyPair::generate()
    {
        MLKEM768KeyPair keys;

        cleared_uarray<size_t{2} * MLKEM_SYMBYTES> rnd;
        random_fill(rnd);

        if (0 != sr_mlkem768_keypair_derand(keys.pub.udata(), keys.sec.udata(), rnd.data()))
            throw std::runtime_error{"ML-KEM-768 keygen failed!"};
        return keys;
    }

    MLKEMSharedSecret MLKEM768SecKey::decapsulate(const MLKEM768Ciphertext& ct) const
    {
        MLKEMSharedSecret ss;
        if (0 != sr_mlkem768_dec(ss.udata(), ct.udata(), udata()))
            throw std::runtime_error{"ML-KEM-768 decapsulation failed!"};
        return ss;
    }

    std::pair<MLKEM768Ciphertext, MLKEMSharedSecret> MLKEM768PubKey::encapsulate() const
    {
        std::pair<MLKEM768Ciphertext, MLKEMSharedSecret> result;
        auto& [ct, ss] = result;

        cleared_uarray<MLKEM_SYMBYTES> rnd;
        random_fill(rnd);

        if (0 != sr_mlkem768_enc_derand(ct.udata(), ss.udata(), udata(), rnd.data()))
            throw std::runtime_error{"ML-KEM-768 encapsulation failed!"};

        return result;
    }

    namespace
    {

        constexpr auto ss_context_key = "srouter session context"sv;

        template <typename... More>
        void hash_add(crypto_generichash_blake2b_state& st, std::span<const std::byte> part, More&&... args)
        {
            crypto_generichash_blake2b_update(&st, reinterpret_cast<const unsigned char*>(part.data()), part.size());
            if constexpr (sizeof...(args))
                hash_add(st, std::forward<More>(args)...);
        }
    }  // namespace

    std::pair<SymmKey, SymmKey> session_secret(
        const RouterID& initiator,
        const RouterID& receiver,
        const X25519KeyPair& a,
        const X25519PubKey& B,
        bool is_initiator,
        const MLKEMSharedSecret& k_s,
        const MLKEM768PubKey& M,
        uint32_t tag_i,
        uint32_t tag_r)
    {
        std::array<std::byte, sizeof(tag_i)> tag_i_bytes, tag_r_bytes;
        oxenc::write_host_as_little(tag_i, tag_i_bytes.data());
        oxenc::write_host_as_little(tag_r, tag_r_bytes.data());

        cleared_uc64 ss_context_hash;
        crypto_generichash_blake2b_state st;
        crypto_generichash_blake2b_init(
            &st,
            reinterpret_cast<const unsigned char*>(ss_context_key.data()),
            ss_context_key.size(),
            ss_context_hash.size());
        hash_add(st, initiator, receiver, tag_i_bytes, tag_r_bytes);

        crypto_generichash_blake2b_final(&st, ss_context_hash.data(), ss_context_hash.size());

        static_assert(2 * SymmKey::size() <= crypto_generichash_blake2b_KEYBYTES_MAX);

        const auto& X = is_initiator ? a.pub : B;
        const auto& Y = is_initiator ? B : a.pub;

        crypto_generichash_blake2b_init(&st, ss_context_hash.data(), ss_context_hash.size(), 2 * SymmKey::size());
        hash_add(st, a.sec * B, X, Y, k_s, M);

        cleared_uc64 shared_secret;
        static_assert(sizeof(cleared_uc64) == 2 * SymmKey::size());
        crypto_generichash_blake2b_final(&st, shared_secret.data(), shared_secret.size());

        auto k1 = std::span{shared_secret}.first<SymmKey::size()>();
        auto k2 = std::span{shared_secret}.last<SymmKey::size()>();

        std::pair<SymmKey, SymmKey> keys;
        auto& [key_in, key_out] = keys;
        key_out.assign(is_initiator ? k1 : k2);
        key_in.assign(is_initiator ? k2 : k1);

        return keys;
    }
}  // namespace srouter
