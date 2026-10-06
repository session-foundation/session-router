#pragma once

#include "address/address.hpp"
#include "contact/router_id.hpp"
#include "keys.hpp"

#include <cstdint>

namespace srouter
{
    using namespace std::literals;
}

namespace srouter::crypto
{
    /// Decrypt cipherText given the key generated from name, for ONS name encryption.
    std::optional<NetworkAddress> maybe_decrypt_name(
        std::string_view ciphertext, const SymmNonce& nonce, std::string_view name);

    /// xchacha symmetric cipher
    void xchacha20(std::span<std::byte> buf, const SymmKey&, const SymmNonce&);

    /// Size of the xchacha20+poly1305 authenticated encryption tag.
    inline constexpr size_t TAG_SIZE = 16;

    /// Encrypts a buffer in-place, putting the tag (which functions as a MAC), in the final bytes
    /// (which must be allocated in the span but are not part of the data that is actually
    /// encrypted).
    ///
    /// That is: this encrypts `[buf.begin(), buf.end() - TAG_SIZE)` and writes the encrypted value
    /// and tag into `[buf.begin(), buf.end())`.  Any existing data in the last TAG_SIZE bytes is
    /// ignored and overwritten.
    void xchacha20_poly1305_encrypt_inplace(std::span<std::byte> buf, const SymmKey& secret, const SymmNonce& nonce);
    void xchacha20_poly1305_encrypt_inplace(std::string& buf, const SymmKey& secret, const SymmNonce& nonce);

    /// Encrypts a value, allocating a new vector to hold it.
    [[nodiscard]] std::vector<std::byte> xchacha20_poly1305_encrypt(
        std::span<const std::byte> plaintext, const SymmKey& secret, const SymmNonce& nonce);

    /// decrypts a buffer in-place, validating it against the embedded authentication tag in the
    /// last TAG_SIZE bytes of the input.  Returns std::nullopt if decryption fails, otherwise it
    /// overwrites first N-TAG_SIZE bytes of buf with the decrypted value and returns a subspan of
    /// that data.
    std::optional<std::span<std::byte>> xchacha20_poly1305_decrypt_inplace(
        std::span<std::byte> buf, const SymmKey& secret, const SymmNonce& nonce);

    /// Decryption with allocation of the output buffer.  Returns nullopt if decryption fails.
    [[nodiscard]] std::optional<std::vector<std::byte>> xchacha20_poly1305_decrypt(
        std::span<const std::byte> ciphertext, const SymmKey& secret, const SymmNonce& nonce);

    /// path dh creator's side
    ///
    /// Note that the input "nonce" here is used domain separation in the shared secret generation,
    /// but isn't used as an encryption nonce (i.e. the same nonce can be safely used for both
    /// shared secret generation and an initial payload encryption).
    bool dh_client(
        SymmKey& out, const PubKey& server_pk, const Ed25519SecretKey& client_seckey, const SymmNonce& nonce);

    /// Generates an ephemeral keypair and random nonce, calls dh_client, then returns the resulting
    /// shared secret, the ephemeral pubkey, and the nonce.  Throws std::invalid_argument if the
    /// server pk is not valid.
    std::tuple<SymmKey, PubKey, SymmNonce> dh_client_gen(const PubKey& server_pk);

    /// path dh relay side
    bool dh_server(
        SymmKey& out, const PubKey& client_pk, const Ed25519SecretKey& server_seckey, const SymmNonce& nonce);
    bool dh_server(uint8_t* shared_secret, const uint8_t* other_pk, const uint8_t* local_sk, const uint8_t* nonce);

    /// blake2b 256 bit
    void shorthash(std::span<std::byte, 32> out, std::span<const std::byte> buf);
    AlignedBuffer<32> shorthash(std::span<const std::byte> buf);

    /// Returns the Ed25519 scalar used for blinding of the given pubkey with the given
    /// blind_domain.  See `blind`.
    ///
    /// This scalar can be used with either the root private scalar or
    /// the root pubkey to produce the blinded private scalar or blinded pubkey, respectively.
    ///
    /// `pubkey` is usually simply passed via implicit conversion from a `PubKey` argument.
    std::array<unsigned char, 32> blinding_scalar(std::span<const std::byte, 32> pubkey, std::string_view blind_domain);

    /// Derive a blinded pubkey from a root pubkey and blinding domain and stores it in `derived`.
    ///
    /// blind_domain should be between 0 and 64 characters long (longer values will be truncated),
    /// and generally should be one of the constants defined below.  A different blind_domain should
    /// be used for each distinct blinding type, and will produce unrelated blinded keys.
    ///
    /// Returns true if successful, false if `root` is not a valid pubkey.
    bool blind(PubKey& blinded, const PubKey& root, std::string_view blind_domain);

    // Known values for the `blind_domain` argument of blind(), blinding_scalar(), and the
    // Ed25519BlindedKey constructor.
    namespace blinding
    {
        constexpr auto CLIENT_CONTACT = "SessionRouterClientContact"sv;
    }

    // Verifies that the cached pubkey embedded in `keys` correctly corresponds with the seed value
    // in `keys`; effectively this checks for corruption of the keys value, such as when loading the
    // keypair from disk.
    bool check_pubkey(const Ed25519SecretKey& keys);

    bool check_passwd_hash(std::string pwhash, std::string challenge);

}  // namespace srouter::crypto
