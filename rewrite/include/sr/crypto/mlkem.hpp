#pragma once

#include <sr/crypto/types.hpp>

#include <span>
#include <vector>

namespace sr::crypto
{

    // ML-KEM-768 post-quantum key encapsulation.
    // Provides post-quantum resistance for session key derivation.
    //
    // Note: upstream uses a bundled ML-KEM implementation.
    // We wrap it with the same interface.

    inline constexpr size_t MLKEM_PK_SIZE = 1184;
    inline constexpr size_t MLKEM_SK_SIZE = 2400;
    inline constexpr size_t MLKEM_CT_SIZE = 1088;
    inline constexpr size_t MLKEM_SS_SIZE = 32;

    struct MLKEMPubKey : Bytes<MLKEM_PK_SIZE>
    {};
    struct MLKEMSecKey : Bytes<MLKEM_SK_SIZE>
    {};
    struct MLKEMCiphertext : Bytes<MLKEM_CT_SIZE>
    {};
    struct MLKEMSharedSecret : Bytes<MLKEM_SS_SIZE>
    {};

    struct MLKEMKeyPair
    {
        MLKEMPubKey pk;
        MLKEMSecKey sk;

        static MLKEMKeyPair generate();
    };

    struct MLKEMEncapResult
    {
        MLKEMCiphertext ct;
        MLKEMSharedSecret ss;
    };

    // Encapsulate: generate ciphertext + shared secret from pubkey.
    MLKEMEncapResult mlkem_encapsulate(const MLKEMPubKey& pk);

    // Decapsulate: recover shared secret from ciphertext + secret key.
    // Returns the shared secret. On failure, returns an implicit rejection
    // value (deterministic but wrong) — no exceptions, no timing oracle.
    MLKEMSharedSecret mlkem_decapsulate(const MLKEMCiphertext& ct, const MLKEMSecKey& sk);

}  // namespace sr::crypto
