#include <sodium.h>
#include <sr/crypto/types.hpp>

#include <mutex>

namespace sr::crypto
{

    static std::once_flag sodium_flag;

    void sodium_init_once()
    {
        std::call_once(sodium_flag, [] {
            if (sodium_init() < 0)
                throw std::runtime_error("libsodium initialization failed");
        });
    }

    Ed25519KeyPair Ed25519KeyPair::generate()
    {
        sodium_init_once();
        Ed25519KeyPair kp;
        crypto_sign_keypair(as_uchar(kp.pk), as_uchar(kp.sk));
        return kp;
    }

    X25519KeyPair X25519KeyPair::generate()
    {
        sodium_init_once();
        X25519KeyPair kp;
        crypto_box_keypair(as_uchar(kp.pk), as_uchar(kp.sk));
        return kp;
    }

    X25519KeyPair X25519KeyPair::from_ed25519(const Ed25519KeyPair& ed)
    {
        X25519KeyPair kp;
        if (crypto_sign_ed25519_pk_to_curve25519(as_uchar(kp.pk), as_uchar(ed.pk)) != 0)
            throw std::runtime_error("Ed25519 → X25519 pubkey conversion failed");
        if (crypto_sign_ed25519_sk_to_curve25519(as_uchar(kp.sk), as_uchar(ed.sk)) != 0)
            throw std::runtime_error("Ed25519 → X25519 seckey conversion failed");
        return kp;
    }

}  // namespace sr::crypto
