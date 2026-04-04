#include <sodium.h>
#include <sr/crypto/session_keys.hpp>

#include <cstring>
#include <endian.h>

namespace sr::crypto
{

    SessionKeys derive_session_keys(
        const X25519PubKey& initiator_x_pk,
        const X25519PubKey& receiver_x_pk,
        const X25519SecKey& our_x_sk,
        const X25519PubKey& their_x_pk,
        bool is_initiator,
        std::span<const std::byte> mlkem_shared_secret,
        std::span<const std::byte> mlkem_pk,
        const Ed25519PubKey& initiator_rid,
        const Ed25519PubKey& receiver_rid,
        uint32_t tag_i,
        uint32_t tag_r)
    {
        // X25519 DH
        unsigned char dh_result[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(dh_result, as_uchar(our_x_sk), as_uchar(their_x_pk)) != 0)
            throw std::runtime_error("session_keys: X25519 scalar multiplication failed");

        // === Phase 1: Context ===
        // context = BLAKE2b-512(
        //   key = "srouter session context",   // 23 bytes exactly
        //   data = I || R || tag_i_le4 || tag_r_le4
        // )
        static constexpr std::string_view ctx_domain = "srouter session context";

        Bytes<64> context;
        {
            crypto_generichash_state state;
            crypto_generichash_init(
                &state,
                reinterpret_cast<const unsigned char*>(ctx_domain.data()),
                ctx_domain.size(),
                64);

            // I = initiator Ed25519 pubkey (RouterID), 32 bytes
            crypto_generichash_update(&state, as_uchar(initiator_rid), initiator_rid.size());
            // R = receiver Ed25519 pubkey (RouterID), 32 bytes
            crypto_generichash_update(&state, as_uchar(receiver_rid), receiver_rid.size());
            // tag_i = initiator session tag, uint32 little-endian, 4 bytes
            uint32_t tag_i_le = htole32(tag_i);
            crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(&tag_i_le), 4);
            // tag_r = receiver session tag, uint32 little-endian, 4 bytes
            uint32_t tag_r_le = htole32(tag_r);
            crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(&tag_r_le), 4);

            crypto_generichash_final(&state, as_uchar(context), 64);
        }

        // === Phase 2: Key derivation ===
        // [k1, k2] = BLAKE2b-512(
        //   key = context,                       // 64 bytes (full Phase 1 output)
        //   data = DH_result || X || Y || k_s || M
        // )
        Bytes<64> h;
        {
            crypto_generichash_state state;
            crypto_generichash_init(&state, as_uchar(context), 64, 64);

            // DH_result = X25519 scalar mult, 32 bytes
            crypto_generichash_update(&state, dh_result, sizeof(dh_result));
            // X = initiator's ephemeral X25519 pubkey, 32 bytes
            crypto_generichash_update(&state, as_uchar(initiator_x_pk), initiator_x_pk.size());
            // Y = receiver's ephemeral X25519 pubkey, 32 bytes
            crypto_generichash_update(&state, as_uchar(receiver_x_pk), receiver_x_pk.size());
            // k_s = ML-KEM shared secret, 32 bytes
            crypto_generichash_update(
                &state, reinterpret_cast<const unsigned char*>(mlkem_shared_secret.data()), mlkem_shared_secret.size());
            // M = initiator's ML-KEM-768 pubkey, 1184 bytes
            crypto_generichash_update(
                &state, reinterpret_cast<const unsigned char*>(mlkem_pk.data()), mlkem_pk.size());

            crypto_generichash_final(&state, as_uchar(h), 64);
        }

        sodium_memzero(dh_result, sizeof(dh_result));
        sodium_memzero(context.data(), context.size());

        // Split: k1 = first 32 bytes, k2 = last 32 bytes
        // CONSTRAINT: initiator uses (out=k1, in=k2), receiver uses (out=k2, in=k1)
        SessionKeys keys;
        if (is_initiator)
        {
            std::memcpy(keys.key_out.data(), h.data(), 32);
            std::memcpy(keys.key_in.data(), reinterpret_cast<const std::byte*>(h.data()) + 32, 32);
        }
        else
        {
            std::memcpy(keys.key_out.data(), reinterpret_cast<const std::byte*>(h.data()) + 32, 32);
            std::memcpy(keys.key_in.data(), h.data(), 32);
        }

        sodium_memzero(h.data(), h.size());
        return keys;
    }

}  // namespace sr::crypto
