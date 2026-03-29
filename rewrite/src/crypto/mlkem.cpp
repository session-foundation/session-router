#include <sodium.h>
#include <sr/crypto/mlkem.hpp>

// ML-KEM-768 implementation.
// TODO: Link against upstream sr_mlkem768 or a standalone ML-KEM library.
// For now, this is a placeholder that generates random shared secrets.
// The interface is correct; the cryptographic implementation needs to be
// swapped in before any real use.

namespace sr::crypto
{

    MLKEMKeyPair MLKEMKeyPair::generate()
    {
        sodium_init_once();
        MLKEMKeyPair kp;
        // PLACEHOLDER: fill with random bytes
        // Real implementation: sr_mlkem768_keypair_derand(pk, sk, random)
        randombytes_buf(kp.pk.data(), kp.pk.size());
        randombytes_buf(kp.sk.data(), kp.sk.size());
        return kp;
    }

    MLKEMEncapResult mlkem_encapsulate(const MLKEMPubKey& pk)
    {
        MLKEMEncapResult result;
        // PLACEHOLDER: fill with random bytes
        // Real implementation: sr_mlkem768_enc_derand(ct, ss, pk, random)
        randombytes_buf(result.ct.data(), result.ct.size());
        randombytes_buf(result.ss.data(), result.ss.size());
        (void)pk;
        return result;
    }

    MLKEMSharedSecret mlkem_decapsulate(const MLKEMCiphertext& ct, const MLKEMSecKey& sk)
    {
        MLKEMSharedSecret ss;
        // PLACEHOLDER: fill with random bytes
        // Real implementation: sr_mlkem768_dec(ss, ct, sk)
        // Note: real ML-KEM returns implicit rejection (deterministic wrong value),
        // NOT an error. No exceptions, no timing oracle.
        randombytes_buf(ss.data(), ss.size());
        (void)ct;
        (void)sk;
        return ss;
    }

}  // namespace sr::crypto
