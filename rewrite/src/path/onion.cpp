#include <sr/path/onion.hpp>
#include <sr/crypto/dh.hpp>
#include <sr/crypto/aead.hpp>

#include <cstring>
#include <sodium.h>

namespace sr::path {

using namespace sr::crypto;

PathBuildResult build_onion(
    const std::vector<sr::contact::RelayContact>& relays,
    const Ed25519KeyPair& ephemeral_keys,
    std::chrono::seconds lifetime)
{
    PathBuildResult result;
    size_t n_hops = relays.size();

    // Initialize all frames with random data (dummy frames for anonymity)
    randombytes_buf(result.frames.data(), result.frames.size());

    // Build hops
    result.hops.resize(n_hops);
    for (size_t i = 0; i < n_hops; ++i) {
        auto& hop = result.hops[i];
        hop.router_id = relays[i].router_id();
        hop.rxid = random_hop_id();
        hop.txid = random_hop_id();
    }

    // Build frames in REVERSE order (pivot to edge)
    // CONSTRAINT: onion frames encrypted in reverse
    for (int i = static_cast<int>(n_hops) - 1; i >= 0; --i) {
        auto& hop = result.hops[i];

        // Generate nonce for this hop's DH
        Nonce nonce;
        randombytes_buf(nonce.data(), nonce.size());

        // DH with this hop's relay
        // We are always "client", relay is always "server"
        hop.shared_secret = dh(
            ephemeral_keys.pk,
            relays[i].router_id().pubkey(),
            ephemeral_keys.sk,
            relays[i].router_id().pubkey(),
            nonce);

        hop.xor_nonce = derive_xor_nonce(hop.shared_secret);

        // Build this hop's frame payload:
        // rxid(16) + txid(16) + upstream(32) + lifetime(4)
        std::array<std::byte, 68> payload{};
        std::memcpy(payload.data(), hop.rxid.data(), 16);
        std::memcpy(payload.data() + 16, hop.txid.data(), 16);

        // Upstream: previous hop's RouterID (or zeros for edge)
        if (i > 0) {
            auto& prev_rid = result.hops[i - 1].router_id.pubkey();
            std::memcpy(payload.data() + 32, prev_rid.data(), 32);
        }

        // Lifetime in seconds (4 bytes, little-endian)
        auto lt = static_cast<uint32_t>(lifetime.count());
        std::memcpy(payload.data() + 64, &lt, 4);

        // Build frame: ephemeral_pk(32) + nonce(24) + encrypted_payload
        auto frame_start = result.frames.data() + i * BUILD_FRAME_SIZE;
        std::memcpy(frame_start, ephemeral_keys.pk.data(), 32);
        std::memcpy(frame_start + 32, nonce.data(), 24);

        // Encrypt payload with shared secret
        SymmetricKey sym_key;
        std::memcpy(sym_key.data(), hop.shared_secret.data(), 32);

        std::array<std::byte, 68> encrypted_payload = payload;
        xchacha20_inplace(encrypted_payload, sym_key, nonce);
        std::memcpy(frame_start + 56, encrypted_payload.data(),
                    std::min(sizeof(encrypted_payload), BUILD_FRAME_SIZE - 56));

        // Onion-encrypt ALL subsequent frames with this hop's key
        // This is the layered encryption that each relay peels
        for (size_t j = i + 1; j < BUILD_LENGTH; ++j) {
            auto other_frame = std::span<std::byte>(
                result.frames.data() + j * BUILD_FRAME_SIZE,
                BUILD_FRAME_SIZE);

            // XOR nonce for onion layer
            Nonce onion_nonce = nonce;
            for (size_t k = 0; k < onion_nonce.size(); ++k)
                onion_nonce[k] ^= hop.xor_nonce[k];

            xchacha20_inplace(other_frame, sym_key, onion_nonce);
        }
    }

    return result;
}

std::optional<DecryptedFrame> decrypt_build_frame(
    std::span<const std::byte> frame,
    const Ed25519SecKey& our_sk,
    const Ed25519PubKey& our_pk)
{
    if (frame.size() < BUILD_FRAME_SIZE)
        return std::nullopt;

    // Extract ephemeral pubkey and nonce
    Ed25519PubKey their_pk;
    std::memcpy(their_pk.data(), frame.data(), 32);

    Nonce nonce;
    std::memcpy(nonce.data(), frame.data() + 32, 24);

    // DH: we are "server", they are "client"
    auto shared = dh(their_pk, our_pk, our_sk, their_pk, nonce);
    auto xor_nonce = derive_xor_nonce(shared);

    // Decrypt payload
    SymmetricKey sym_key;
    std::memcpy(sym_key.data(), shared.data(), 32);

    size_t payload_size = BUILD_FRAME_SIZE - 56;
    std::vector<std::byte> payload(frame.data() + 56, frame.data() + 56 + payload_size);
    xchacha20_inplace(payload, sym_key, nonce);

    // Parse: rxid(16) + txid(16) + upstream(32) + lifetime(4)
    if (payload.size() < 68)
        return std::nullopt;

    DecryptedFrame df;
    std::memcpy(df.rxid.data(), payload.data(), 16);
    std::memcpy(df.txid.data(), payload.data() + 16, 16);
    Ed25519PubKey upstream_pk;
    std::memcpy(upstream_pk.data(), payload.data() + 32, 32);
    df.upstream = sr::contact::RouterID{upstream_pk};

    uint32_t lt;
    std::memcpy(&lt, payload.data() + 64, 4);
    df.lifetime = std::chrono::seconds(lt);

    df.shared_secret = shared;
    df.xor_nonce = xor_nonce;

    return df;
}

}  // namespace sr::path
