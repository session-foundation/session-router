#pragma once

#include "contact/router_id.hpp"
#include "util/aligned.hpp"

#include <concepts>

namespace srouter
{
    // X25519 keys: these are used (along with ML-KEM) for session secret key negotiation.
    struct X25519PubKey : public AlignedBuffer<32>
    {
        using AlignedBuffer<32>::AlignedBuffer;

        // Constructs an X25519PubKey by converting the given Ed25519 pubkey into X25519.
        explicit X25519PubKey(const PubKey& ed_pk);
    };

    struct X25519SecKey : public AlignedBuffer<32, true>
    {
        using AlignedBuffer<32, true>::AlignedBuffer;

        // Constructs an X25519SecKey by converting the given Ed25519 secret key into a X25519
        // private key.  If you also need the pubkey, see instead the X25519KeyPair constructor.
        explicit X25519SecKey(const Ed25519SecretKey& ed_sk);

        // Calculates the pubkey associated with this private key.
        [[nodiscard]] X25519PubKey to_pubkey() const;

        // Multiplies an X25519 pubkey by this private key scalar.  i.e. `a * B;` is the code
        // equivalent of crypto math expression `aB`.
        [[nodiscard]] X25519PubKey operator*(const X25519PubKey& pk) const;
    };
    struct X25519KeyPair
    {
        X25519PubKey pub;
        X25519SecKey sec;

        [[nodiscard]] static X25519KeyPair generate();

        X25519KeyPair() = default;
        explicit X25519KeyPair(const Ed25519SecretKey& ed_sk);
    };

    // The ML-KEM-768 ciphertext that the receiver sends back to the initiator, containing a shared
    // secret that only the initiator can obtain.
    struct MLKEM768Ciphertext : public AlignedBuffer<1088>
    {
        using AlignedBuffer<1088>::AlignedBuffer;
    };

    // Holds a fixed, 32-byte shared secret produced by ML-KEM encapsulation, and coming out of
    // ciphertext decapsulation.  (No 768 in the class name because all variations produce the same
    // size shared secret).
    struct MLKEMSharedSecret : public AlignedBuffer<32, true>
    {
        using AlignedBuffer<32, true>::AlignedBuffer;
    };

    // ML-KEM-768 secret key.
    struct MLKEM768SecKey : public AlignedBuffer<2400, true>
    {
        using AlignedBuffer<2400, true>::AlignedBuffer;

        // Takes an ML-KEM ciphertext encapsulated for us and decapsulates it, recovering the
        // 32-byte shared secret from it.  Note that there is no concept of "success" here:
        // decapsulating modified data simple returns a different (incorrect) shared secret.
        [[nodiscard]] MLKEMSharedSecret decapsulate(const MLKEM768Ciphertext& ct) const;
    };

    // ML-KEM-768 pubkey.
    struct MLKEM768PubKey : public AlignedBuffer<1184>
    {
        using AlignedBuffer<1184>::AlignedBuffer;

        // "Encapsulates" a random shared secret for this pubkey.  Returns the ciphertext to be sent
        // to this pubkey to decapsulate from which the key owner can recover the shared secret; and
        // the randomly generated shared secret itself.
        [[nodiscard]] std::pair<MLKEM768Ciphertext, MLKEMSharedSecret> encapsulate() const;

        // Implicit conversion to leancrypto primitives (we verify that these conversions are okay
        // via static asserts in the .cpp).
        template <std::same_as<::lc_kyber_768_pk> T>
        operator T*()
        {
            return reinterpret_cast<::lc_kyber_768_pk*>(data());
        }
        template <std::same_as<::lc_kyber_768_pk> T>
        operator const T*() const
        {
            return reinterpret_cast<const ::lc_kyber_768_pk*>(data());
        }
    };

    struct MLKEM768KeyPair
    {
        MLKEM768PubKey pub;
        MLKEM768SecKey sec;

        [[nodiscard]] static MLKEM768KeyPair generate();
    };

    // Computes the final session shared secret (see description in session/session.hpp) from
    // various key exchange data:
    //
    //        context = blake2b_64(I || R || tagᵢ || tagᵣ, key="srouter session context")
    //
    //        [k₁, k₂] = blake2b_64({yX or xY} || X || Y || kₛ || M, key=context)
    //
    // - I/R are the initiator/recipient long-term Ed25519 pubkeys
    // - tag_i/_r are the initiator/recipient (inbound) session tags
    // - x/X is the initiator ephemeral session X25519 keypair
    // - y/Y is the remote ephemeral session X25519 keypair
    // - k_s is the ML-KEM shared secret
    // - M is the initiator ML-KEM-768 pubkey
    //
    // Arguments are as above, except that:
    // - we take our local ephemeral keypair and the other side's eph pubkey as third/fourth
    //   arguments (a/B), which could be either {x,X} and Y, or {y,Y} and X: The bool argument
    //   following these indicate whether we are computing as the initiator (true) or receiver
    //   (false) to disambiguate.
    //
    // Returned are the inbound traffic shared secret, and the outbound traffic shared secret.
    // (Whether these are k₁ or k₂ depends on whether this is the initiator or not: the initiator
    // encrypts with k₁ and decrypts with k₂, and the receiver does the opposite).
    [[nodiscard]] std::pair<SymmKey, SymmKey> session_secret(
        const RouterID& initiator,
        const RouterID& receiver,
        const X25519KeyPair& a,
        const X25519PubKey& B,
        bool is_initiator,
        const MLKEMSharedSecret& k_s,
        const MLKEM768PubKey& M,
        uint32_t tag_i,
        uint32_t tag_r);

}  // namespace srouter
