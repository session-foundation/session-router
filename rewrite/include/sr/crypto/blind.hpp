#pragma once

#include <sr/crypto/types.hpp>

#include <string_view>

namespace sr::crypto
{

    // Blinded key derivation for client contact privacy.
    // A client publishes its contact under a blinded key so relays
    // cannot link the contact to the real identity.
    //
    // CONSTRAINT: domain strings must be globally unique across all uses.

    namespace blinding
    {
        inline constexpr std::string_view CLIENT_CONTACT = "srouter session context";
    }

    // Derive a blinded pubkey from a root pubkey and domain.
    Ed25519PubKey blind_pubkey(const Ed25519PubKey& root_pk, std::string_view domain);

    // Blinded keypair for signing with a blinded identity.
    struct BlindedKeyPair
    {
        Ed25519PubKey pk;
        // Internal signing state (not a standard Ed25519 secret key)
        Bytes<64> sign_key;
        Bytes<32> hash_data;

        static BlindedKeyPair from_root(
            const Ed25519SecKey& root_sk, const Ed25519PubKey& root_pk, std::string_view domain);

        Signature sign(std::span<const std::byte> message) const;
    };

    // Verify a signature made with a blinded key.
    bool blind_verify(std::span<const std::byte> message, const Signature& sig, const Ed25519PubKey& blinded_pk);

}  // namespace sr::crypto
