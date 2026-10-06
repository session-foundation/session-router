#pragma once

#include "util/aligned.hpp"

struct lc_kyber_768_pk;
struct lc_kyber_768_sk;

namespace srouter
{
    // Holds an Ed25519 signature
    struct Signature final : AlignedBuffer<64>
    {
        using AlignedBuffer<64>::AlignedBuffer;
    };

    // Holds a view of Ed25519 signature data
    struct SignatureView
    {
        std::span<const std::byte, 64> sig_data;

        explicit SignatureView(std::span<const std::byte, 64> sig_data) : sig_data{sig_data} {}
        SignatureView(Signature&& sig) = delete;
        // Implicit conversion from Signature, so that you can pass a Signature where a
        // SignatureView is taken (such as PubKey.verify(...)):
        SignatureView(const Signature& sig) : sig_data{sig.first<64>()} {}
    };

    // Holds an Ed25519 pubkey
    struct PubKey : public AlignedBuffer<32>
    {
        using AlignedBuffer<32>::AlignedBuffer;

        bool from_hex(const std::string& str);

        std::string to_string() const;

        /// Checks whether `signature` is a valid signature created by this pubkey of the given
        /// `message`.
        bool verify(std::span<const std::byte> message, SignatureView signature) const;

        /// Produces a "sealed box" encrypted for this Ed25519 pubkey.
        ///
        /// This first converts the Ed pubkey to an X25519 pubkey, then uses that with libsodium's
        /// sealed box encryption (using the xchacha20 encryption variation rather than the default
        /// xsalsa20 encryption).
        ///
        /// Decrypt via Ed25519SecretKey::unseal_box.
        std::vector<std::byte> seal_box(std::span<const std::byte> message) const;
    };

    /// Stores a sodium "secret key" value, which is actually the Ed25519 seed
    /// concatenated with the public key.  Note that the seed is *not* the private
    /// key value itself, but rather the seed from which it can be calculated.
    struct Ed25519SecretKey final : AlignedBuffer<64, true>
    {
        using AlignedBuffer<64, true>::AlignedBuffer;

        // If constructed with just the seed, we recalculate the pubkey
        explicit Ed25519SecretKey(const AlignedBuffer<32>& seed)
        {
            std::memcpy(data(), seed.data(), seed.size());
            recalculate();
        }

        // Generates a new random key
        static Ed25519SecretKey generate();

        /// recalculate public component (last 32 bytes) from leading 32-byte seed component
        void recalculate();

        /// Verifies that the public component matches the seed component
        bool check_pubkey() const;

        std::span<const std::byte, 32> pubkey_span() const { return span().last<32>(); }
        PubKey to_pubkey() const { return PubKey{pubkey_span()}; }

        Signature sign(std::span<const std::byte> buf) const;
        void sign(std::span<std::byte, Signature::size()> out, std::span<const std::byte> buf) const;

        // Unseals (i.e. decrypts and verifies) a sealed box allegedly sealed for us, as produced by
        // PubKey::seal_box(...).  Throws std::runtime_error if decryption fails; otherwise returns
        // the decrypted message.
        std::vector<std::byte> unseal_box(std::span<const std::byte> ciphertext) const;

        static constexpr bool to_string_formattable{false};
    };

    /// Stores a private scalar, pubkey, and hash_data for a blinded key (typically) derived from a
    /// Ed25519SecretKey.
    struct Ed25519BlindedKey final
    {
        AlignedBuffer<32, true> scalar;
        AlignedBuffer<32, true> hash_data;
        PubKey pubkey;

        // Constructs as blinded key as the result of blinding an Ed25519SecretKey
        Ed25519BlindedKey(const Ed25519SecretKey& root, std::string_view blind_domain);

        // Constructs a blinded key from a scalar and hash data.  The pubkey is derived during
        // construction from the scalar.
        Ed25519BlindedKey(std::span<const std::byte, 32> scalar, std::span<const std::byte, 32> hash_data);

        // Produces an Ed25519 signature that validates with this blinded key's pubkey
        Signature sign(std::span<const std::byte> buf) const;
        void sign(std::span<std::byte, Signature::size()> out, std::span<const std::byte> buf) const;

        static constexpr bool to_string_formattable{false};
    };

    // Buffer for holding a 32-byte value used as a symmetric key.  Additionally, safely clears the
    // buffer during destruction.
    struct SymmKey : AlignedBuffer<32, true>
    {
        using AlignedBuffer<32, true>::AlignedBuffer;
    };

    // Nonce used in xchacha20 encryption
    struct SymmNonce final : AlignedBuffer<24>
    {
        using AlignedBuffer<24>::AlignedBuffer;

        SymmNonce operator^(const SymmNonce& other) const
        {
            SymmNonce ret;
            std::transform(begin(), end(), other.begin(), ret.begin(), std::bit_xor<>());
            return ret;
        }

        static SymmNonce make_random();
    };

}  // namespace srouter

namespace std
{
    template <>
    struct hash<srouter::PubKey> : public hash<srouter::AlignedBuffer<srouter::PubKey::size()>>
    {};
}  //  namespace std
