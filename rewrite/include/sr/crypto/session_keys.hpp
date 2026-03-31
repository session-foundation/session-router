#pragma once

#include <sr/crypto/types.hpp>

namespace sr::crypto
{

    // Session key derivation — upstream-compatible two-phase BLAKE2b.
    //
    // Phase 1 — Context:
    //   context = BLAKE2b-512(key="srouter session context",
    //                         data=I||R||tag_i_le4||tag_r_le4)
    //
    // Phase 2 — Key material:
    //   [k1,k2] = BLAKE2b-512(key=context,
    //                          data=DH_result||X||Y||k_s||M)
    //
    // CONSTRAINT: Initiator uses (out=k1, in=k2), receiver uses (out=k2, in=k1).

    struct SessionKeys
    {
        SymmetricKey key_out;
        SymmetricKey key_in;
    };

    SessionKeys derive_session_keys(
        const X25519PubKey& initiator_x_pk,  // X (always initiator's)
        const X25519PubKey& receiver_x_pk,   // Y (always receiver's)
        const X25519SecKey& our_x_sk,
        const X25519PubKey& their_x_pk,
        bool is_initiator,
        std::span<const std::byte> mlkem_shared_secret,
        std::span<const std::byte> mlkem_pk,
        const Ed25519PubKey& initiator_rid,
        const Ed25519PubKey& receiver_rid,
        uint32_t tag_i = 0,   // initiator session tag
        uint32_t tag_r = 0);  // receiver session tag

}  // namespace sr::crypto
