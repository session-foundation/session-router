#pragma once

#include <sr/crypto/types.hpp>

namespace sr::crypto
{

    // Session key derivation.
    // Combines X25519 DH and ML-KEM shared secret into symmetric session keys.
    //
    // CONSTRAINT: Initiator uses (out=k1, in=k2), receiver uses (out=k2, in=k1).
    // CONSTRAINT: Hash input ordering must match upstream exactly.

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
        const Ed25519PubKey& receiver_rid);

}  // namespace sr::crypto
