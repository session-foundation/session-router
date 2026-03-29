#include <sr/session/session.hpp>

#include <cstring>
#include <sodium.h>

namespace sr::session {

using namespace sr::crypto;

SessionTag random_tag() {
    sodium_init_once();
    SessionTag tag;
    randombytes_buf(tag.data(), tag.size());
    return tag;
}

Session Session::from_keys(const SessionKeys& keys, const SessionTag& tag) {
    Session s;
    s._keys = keys;
    s._tag = tag;
    s._established = true;
    return s;
}

std::vector<std::byte> Session::encrypt(
    std::span<const std::byte> plaintext,
    TrafficType type) const
{
    // Build nonce from counter (deterministic, no reuse with same key)
    Nonce nonce{};
    auto counter = _nonce_counter++;
    std::memcpy(nonce.data(), &counter, sizeof(counter));

    // Payload = plaintext + type byte
    std::vector<std::byte> payload(plaintext.size() + 1);
    std::memcpy(payload.data(), plaintext.data(), plaintext.size());
    payload.back() = static_cast<std::byte>(type);

    // AEAD encrypt
    auto ct = aead_encrypt(payload, _keys.key_out, nonce);

    // Prepend session tag + nonce
    std::vector<std::byte> msg;
    msg.reserve(4 + AEAD_NONCE_SIZE + ct.size());
    msg.insert(msg.end(), _tag.begin(), _tag.end());
    msg.insert(msg.end(), nonce.begin(), nonce.end());
    msg.insert(msg.end(), ct.begin(), ct.end());

    return msg;
}

std::optional<std::vector<std::byte>> Session::decrypt(
    std::span<const std::byte> ciphertext) const
{
    // Minimum: tag(4) + nonce(24) + tag_size(16)
    if (ciphertext.size() < 4 + AEAD_NONCE_SIZE + AEAD_TAG_SIZE)
        return std::nullopt;

    // Extract nonce (skip tag)
    Nonce nonce;
    std::memcpy(nonce.data(), ciphertext.data() + 4, AEAD_NONCE_SIZE);

    // Decrypt
    auto ct_data = ciphertext.subspan(4 + AEAD_NONCE_SIZE);
    auto pt = aead_decrypt(ct_data, _keys.key_in, nonce);
    if (!pt || pt->empty())
        return std::nullopt;

    // Strip type byte
    pt->pop_back();
    return pt;
}

// SessionInit seal/unseal
std::vector<std::byte> SessionInit::seal_for(
    const Ed25519PubKey& recipient,
    [[maybe_unused]] const Ed25519SecKey& our_sk) const
{
    // Serialize: identity(32) + x_pubkey(32) + mlkem_pubkey(1184) + signature(64) + tag(4)
    std::vector<std::byte> payload;
    payload.reserve(32 + 32 + MLKEM_PK_SIZE + 64 + 4);
    payload.insert(payload.end(), identity.begin(), identity.end());
    payload.insert(payload.end(), x_pubkey.begin(), x_pubkey.end());
    payload.insert(payload.end(), mlkem_pubkey.begin(), mlkem_pubkey.end());
    payload.insert(payload.end(), signature.begin(), signature.end());
    payload.insert(payload.end(), tag.begin(), tag.end());

    return seal(payload, recipient);
}

std::optional<SessionInit> SessionInit::unseal(
    std::span<const std::byte> sealed_data,
    const Ed25519PubKey& our_pk,
    const Ed25519SecKey& our_sk)
{
    auto payload = sr::crypto::unseal(sealed_data, our_pk, our_sk);
    if (!payload)
        return std::nullopt;

    size_t expected = 32 + 32 + MLKEM_PK_SIZE + 64 + 4;
    if (payload->size() < expected)
        return std::nullopt;

    SessionInit si;
    size_t off = 0;
    std::memcpy(si.identity.data(), payload->data() + off, 32); off += 32;
    std::memcpy(si.x_pubkey.data(), payload->data() + off, 32); off += 32;
    std::memcpy(si.mlkem_pubkey.data(), payload->data() + off, MLKEM_PK_SIZE); off += MLKEM_PK_SIZE;
    std::memcpy(si.signature.data(), payload->data() + off, 64); off += 64;
    std::memcpy(si.tag.data(), payload->data() + off, 4);
    return si;
}

// SessionAccept seal/unseal
std::vector<std::byte> SessionAccept::seal_for(
    const Ed25519PubKey& recipient,
    [[maybe_unused]] const Ed25519SecKey& our_sk) const
{
    std::vector<std::byte> payload;
    payload.reserve(32 + MLKEM_CT_SIZE + 64 + 4);
    payload.insert(payload.end(), x_pubkey.begin(), x_pubkey.end());
    payload.insert(payload.end(), mlkem_ciphertext.begin(), mlkem_ciphertext.end());
    payload.insert(payload.end(), signature.begin(), signature.end());
    payload.insert(payload.end(), tag.begin(), tag.end());

    return seal(payload, recipient);
}

std::optional<SessionAccept> SessionAccept::unseal(
    std::span<const std::byte> sealed_data,
    const Ed25519PubKey& our_pk,
    const Ed25519SecKey& our_sk)
{
    auto payload = sr::crypto::unseal(sealed_data, our_pk, our_sk);
    if (!payload)
        return std::nullopt;

    size_t expected = 32 + MLKEM_CT_SIZE + 64 + 4;
    if (payload->size() < expected)
        return std::nullopt;

    SessionAccept sa;
    size_t off = 0;
    std::memcpy(sa.x_pubkey.data(), payload->data() + off, 32); off += 32;
    std::memcpy(sa.mlkem_ciphertext.data(), payload->data() + off, MLKEM_CT_SIZE); off += MLKEM_CT_SIZE;
    std::memcpy(sa.signature.data(), payload->data() + off, 64); off += 64;
    std::memcpy(sa.tag.data(), payload->data() + off, 4);
    return sa;
}

}  // namespace sr::session
