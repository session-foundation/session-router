#include <sodium.h>
#include <sr/crypto/aead.hpp>
#include <sr/crypto/bt.hpp>
#include <sr/crypto/dh.hpp>
#include <sr/path/onion.hpp>

#include <cstring>

namespace sr::path
{

    using namespace sr::crypto;
    using namespace sr::encoding;

    // Build the inner payload as a BT dict:
    // {"l":lifetime_le4, "r":rxid, "t":txid, "u":upstream_rid}
    static std::string build_inner_bt(
        const HopID& rxid,
        const HopID& txid,
        const Ed25519PubKey& upstream_rid,
        uint32_t lifetime_secs)
    {
        oxenc::bt_dict_producer dp{};

        // "l" -> lifetime (4 bytes, little-endian)
        std::array<char, 4> lt_buf;
        std::memcpy(lt_buf.data(), &lifetime_secs, 4);
        dp.append("l", std::string_view{lt_buf.data(), 4});

        // "r" -> rxID (16 bytes)
        dp.append("r", std::string_view{reinterpret_cast<const char*>(rxid.data()), 16});

        // "t" -> txID (16 bytes)
        dp.append("t", std::string_view{reinterpret_cast<const char*>(txid.data()), 16});

        // "u" -> upstream RouterID (32 bytes)
        dp.append("u", std::string_view{reinterpret_cast<const char*>(upstream_rid.data()), 32});

        return std::move(dp).str();
    }

    // Build a single frame as BT dict:
    // {"k":ephemeral_pk, "n":nonce, "x":encrypted_inner}
    static void build_frame(
        std::byte* frame_out,
        const Ed25519PubKey& eph_pk,
        const Nonce& nonce,
        const std::string& encrypted_inner)
    {
        oxenc::bt_dict_producer dp{};

        // "k" -> ephemeral public key (32 bytes)
        dp.append("k", std::string_view{reinterpret_cast<const char*>(eph_pk.data()), 32});

        // "n" -> nonce (24 bytes)
        dp.append("n", std::string_view{reinterpret_cast<const char*>(nonce.data()), 24});

        // "x" -> encrypted inner payload
        dp.append("x", encrypted_inner);

        auto frame_str = std::move(dp).str();

        // The frame must be exactly BUILD_FRAME_SIZE bytes.
        // Pad with zeros if shorter (shouldn't happen with correct payload sizes).
        if (frame_str.size() <= BUILD_FRAME_SIZE)
        {
            std::memcpy(frame_out, frame_str.data(), frame_str.size());
            if (frame_str.size() < BUILD_FRAME_SIZE)
                std::memset(frame_out + frame_str.size(), 0, BUILD_FRAME_SIZE - frame_str.size());
        }
        else
        {
            // Truncate if somehow larger (shouldn't happen)
            std::memcpy(frame_out, frame_str.data(), BUILD_FRAME_SIZE);
        }
    }

    PathBuildResult build_onion(
        const std::vector<sr::contact::RelayContact>& relays,
        const Ed25519KeyPair& ephemeral_keys,
        std::chrono::seconds lifetime)
    {
        PathBuildResult result;
        size_t n_hops = relays.size();

        // Initialize all frames with random data (dummy frames for anonymity)
        randombytes_buf(result.frames.data(), result.frames.size());

        // Build hops with correct ID chaining:
        // Hop 0: rxid = random, txid = random
        // Hop N (N>0): rxid = hop[N-1].txid
        // Pivot hop: txid = rxid
        result.hops.resize(n_hops);
        for (size_t i = 0; i < n_hops; ++i)
        {
            auto& hop = result.hops[i];
            hop.router_id = relays[i].router_id();

            if (i == 0)
            {
                hop.rxid = random_hop_id();
            }
            else
            {
                hop.rxid = result.hops[i - 1].txid;
            }

            if (i == n_hops - 1)
            {
                // Pivot hop: txid = rxid
                hop.txid = hop.rxid;
            }
            else
            {
                hop.txid = random_hop_id();
            }
        }

        auto lt_secs = static_cast<uint32_t>(lifetime.count());

        // Build frames in REVERSE order (pivot to edge)
        for (int i = static_cast<int>(n_hops) - 1; i >= 0; --i)
        {
            auto& hop = result.hops[i];

            // Generate nonce for this hop's DH
            Nonce nonce;
            randombytes_buf(nonce.data(), nonce.size());

            // DH with this hop's relay
            hop.shared_secret =
                dh(ephemeral_keys.pk,
                   relays[i].router_id().pubkey(),
                   ephemeral_keys.sk,
                   relays[i].router_id().pubkey(),
                   nonce);

            hop.xor_nonce = derive_xor_nonce(hop.shared_secret);

            // Upstream: previous hop's RouterID (or zeros for edge)
            Ed25519PubKey upstream_pk{};
            if (i > 0)
            {
                upstream_pk = result.hops[i - 1].router_id.pubkey();
            }

            // Build inner BT payload
            auto inner_bt = build_inner_bt(hop.rxid, hop.txid, upstream_pk, lt_secs);

            // Encrypt inner payload with shared secret
            SymmetricKey sym_key;
            std::memcpy(sym_key.data(), hop.shared_secret.data(), 32);

            // Convert to bytes for encryption
            std::vector<std::byte> inner_bytes(inner_bt.size());
            std::memcpy(inner_bytes.data(), inner_bt.data(), inner_bt.size());
            xchacha20_inplace(inner_bytes, sym_key, nonce);

            // Encrypted inner as string for BT encoding
            std::string encrypted_inner{
                reinterpret_cast<const char*>(inner_bytes.data()), inner_bytes.size()};

            // Build frame BT dict
            auto frame_start = result.frames.data() + i * BUILD_FRAME_SIZE;
            build_frame(frame_start, ephemeral_keys.pk, nonce, encrypted_inner);

            // Onion-encrypt ALL subsequent REAL frames (not dummies) with this hop's key
            for (size_t j = i + 1; j < n_hops; ++j)
            {
                auto other_frame = std::span<std::byte>(
                    result.frames.data() + j * BUILD_FRAME_SIZE, BUILD_FRAME_SIZE);

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
        std::span<const std::byte> frame, const Ed25519SecKey& our_sk, const Ed25519PubKey& our_pk)
    {
        if (frame.size() < BUILD_FRAME_SIZE)
            return std::nullopt;

        try
        {
            // Parse the frame as BT dict: {"k":..., "n":..., "x":...}
            auto sv = to_sv(frame.first(BUILD_FRAME_SIZE));
            oxenc::bt_dict_consumer dc{sv};

            // "k" -> ephemeral pubkey
            if (!dc.skip_until("k"))
                return std::nullopt;
            auto k_sv = dc.consume_string_view();
            if (k_sv.size() < 32)
                return std::nullopt;
            Ed25519PubKey their_pk;
            std::memcpy(their_pk.data(), k_sv.data(), 32);

            // "n" -> nonce
            if (!dc.skip_until("n"))
                return std::nullopt;
            auto n_sv = dc.consume_string_view();
            if (n_sv.size() < 24)
                return std::nullopt;
            Nonce nonce;
            std::memcpy(nonce.data(), n_sv.data(), 24);

            // "x" -> encrypted inner
            if (!dc.skip_until("x"))
                return std::nullopt;
            auto x_sv = dc.consume_string_view();

            // DH: we are "server", they are "client"
            auto shared = dh(their_pk, our_pk, our_sk, their_pk, nonce);
            auto xor_nonce = derive_xor_nonce(shared);

            // Decrypt inner payload
            SymmetricKey sym_key;
            std::memcpy(sym_key.data(), shared.data(), 32);

            std::vector<std::byte> inner(x_sv.size());
            std::memcpy(inner.data(), x_sv.data(), x_sv.size());
            xchacha20_inplace(inner, sym_key, nonce);

            // Parse inner BT dict: {"l":..., "r":..., "t":..., "u":...}
            auto inner_sv = to_sv(inner);
            oxenc::bt_dict_consumer idc{inner_sv};

            DecryptedFrame df;

            // "l" -> lifetime
            if (!idc.skip_until("l"))
                return std::nullopt;
            auto l_sv = idc.consume_string_view();
            if (l_sv.size() < 4)
                return std::nullopt;
            uint32_t lt;
            std::memcpy(&lt, l_sv.data(), 4);
            df.lifetime = std::chrono::seconds(lt);

            // "r" -> rxid
            if (!idc.skip_until("r"))
                return std::nullopt;
            auto r_sv = idc.consume_string_view();
            if (r_sv.size() < 16)
                return std::nullopt;
            std::memcpy(df.rxid.data(), r_sv.data(), 16);

            // "t" -> txid
            if (!idc.skip_until("t"))
                return std::nullopt;
            auto t_sv = idc.consume_string_view();
            if (t_sv.size() < 16)
                return std::nullopt;
            std::memcpy(df.txid.data(), t_sv.data(), 16);

            // "u" -> upstream RouterID
            if (!idc.skip_until("u"))
                return std::nullopt;
            auto u_sv = idc.consume_string_view();
            if (u_sv.size() < 32)
                return std::nullopt;
            Ed25519PubKey upstream_pk;
            std::memcpy(upstream_pk.data(), u_sv.data(), 32);
            df.upstream = sr::contact::RouterID{upstream_pk};

            df.shared_secret = shared;
            df.xor_nonce = xor_nonce;

            return df;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

}  // namespace sr::path
