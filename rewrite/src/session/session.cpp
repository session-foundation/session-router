#include <sodium.h>
#include <sr/crypto/bt.hpp>
#include <sr/session/session.hpp>

#include <cstring>

namespace sr::session
{

    using namespace sr::crypto;
    using namespace sr::encoding;

    SessionTag random_tag()
    {
        sodium_init_once();
        SessionTag tag;
        randombytes_buf(tag.data(), tag.size());
        return tag;
    }

    uint32_t tag_to_uint(const SessionTag& tag)
    {
        uint32_t val = 0;
        std::memcpy(&val, tag.data(), 4);
        return val;
    }

    SessionTag uint_to_tag(uint32_t val)
    {
        SessionTag tag;
        std::memcpy(tag.data(), &val, 4);
        return tag;
    }

    Session Session::from_keys(const SessionKeys& keys, const SessionTag& tag, const PivotID& pivot)
    {
        Session s;
        s._keys = keys;
        s._tag = tag;
        s._pivot_id = pivot;
        s._established = true;
        return s;
    }

    // Session data messages are NOT BT-encoded (performance path):
    // [Encrypted(PAYLOAD + TYPE_BYTE)] [SESSION_TAG (4 bytes, big-endian)] [PIVOT_ID (16 bytes)]
    // Nonce is NOT in the session message — it is part of the path framing layer.

    std::vector<std::byte> Session::encrypt(
        std::span<const std::byte> plaintext,
        const Nonce& nonce,
        TrafficType type) const
    {
        // Payload = plaintext + type byte (appended BEFORE encryption)
        std::vector<std::byte> payload(plaintext.size() + 1);
        std::memcpy(payload.data(), plaintext.data(), plaintext.size());
        payload.back() = static_cast<std::byte>(type);

        // AEAD encrypt
        auto ct = aead_encrypt(payload, _keys.key_out, nonce);

        // Append session tag (big-endian) and pivot ID AFTER encryption
        std::vector<std::byte> msg;
        msg.reserve(ct.size() + 4 + 16);
        msg.insert(msg.end(), ct.begin(), ct.end());

        // Session tag (4 bytes, big-endian on wire — stored as raw bytes)
        msg.insert(msg.end(), _tag.begin(), _tag.end());

        // Pivot ID (16 bytes)
        msg.insert(msg.end(), _pivot_id.begin(), _pivot_id.end());

        return msg;
    }

    std::optional<std::vector<std::byte>> Session::decrypt(
        std::span<const std::byte> ciphertext,
        const Nonce& nonce) const
    {
        // Minimum: encrypted(1 type byte) + tag(16) + tag(4) + pivot(16)
        if (ciphertext.size() < AEAD_TAG_SIZE + 1 + 4 + 16)
            return std::nullopt;

        // Strip session tag (4 bytes) and pivot ID (16 bytes) from the end
        auto ct_len = ciphertext.size() - 4 - 16;
        auto ct_data = ciphertext.subspan(0, ct_len);

        // Decrypt
        auto pt = aead_decrypt(ct_data, _keys.key_in, nonce);
        if (!pt || pt->empty())
            return std::nullopt;

        // Strip type byte
        pt->pop_back();
        return pt;
    }

    // === SessionInit: BT-encoded with sealed box ===

    std::vector<std::byte> SessionInit::seal_for(
        const Ed25519PubKey& recipient, const Ed25519SecKey& our_sk) const
    {
        // Build inner BT dict (without signature):
        // {"I":pubkey, "M":mlkem, "X":x25519, "p":pivot_hopid, "t":tag}
        std::string inner_prefix;
        {
            oxenc::bt_dict_producer dp{};
            dp.append("I", std::string_view{reinterpret_cast<const char*>(identity.data()), 32});
            dp.append("M", std::string_view{reinterpret_cast<const char*>(mlkem_pubkey.data()), mlkem_pubkey.size()});
            dp.append("X", std::string_view{reinterpret_cast<const char*>(x_pubkey.data()), 32});
            dp.append("p", std::string_view{reinterpret_cast<const char*>(pivot_id.data()), 16});

            // "t" — session tag as uint32 LE encoded as 4-byte string
            uint32_t t = tag_to_uint(tag);
            std::array<char, 4> tag_buf;
            std::memcpy(tag_buf.data(), &t, 4);
            dp.append("t", std::string_view{tag_buf.data(), 4});

            inner_prefix = std::move(dp).str();
        }

        // Remove trailing 'e' to get the signable prefix
        if (!inner_prefix.empty() && inner_prefix.back() == 'e')
            inner_prefix.pop_back();

        // Sign and append "~":signature + closing 'e'
        auto inner_bt = append_signature(inner_prefix, as_uchar(our_sk));
        auto inner_bytes = to_bytes(inner_bt);

        // Seal the inner BT with crypto_box_seal for recipient
        auto sealed = seal(inner_bytes, recipient);

        // Build outer BT dict: {"":"i", "B":<sealed>}
        std::string outer;
        {
            oxenc::bt_dict_producer dp{};
            dp.append("", "i");
            dp.append("B", std::string_view{reinterpret_cast<const char*>(sealed.data()), sealed.size()});
            outer = std::move(dp).str();
        }

        return to_bytes(outer);
    }

    std::optional<SessionInit> SessionInit::unseal(
        std::span<const std::byte> bt_outer, const Ed25519PubKey& our_pk, const Ed25519SecKey& our_sk)
    {
        try
        {
            // Parse outer BT dict
            auto sv = to_sv(bt_outer);
            oxenc::bt_dict_consumer dc{sv};

            // "" -> handshake type
            if (!dc.skip_until(""))
                return std::nullopt;
            auto type = dc.consume_string();
            if (type != "i")
                return std::nullopt;

            // "B" -> sealed box
            if (!dc.skip_until("B"))
                return std::nullopt;
            auto sealed_sv = dc.consume_string_view();
            std::vector<std::byte> sealed_data(
                reinterpret_cast<const std::byte*>(sealed_sv.data()),
                reinterpret_cast<const std::byte*>(sealed_sv.data() + sealed_sv.size()));

            // Unseal
            auto inner = sr::crypto::unseal(sealed_data, our_pk, our_sk);
            if (!inner)
                return std::nullopt;

            // Parse inner BT dict
            auto inner_sv = to_sv(*inner);
            oxenc::bt_dict_consumer idc{inner_sv};

            SessionInit si;

            // "I" -> identity
            if (!idc.skip_until("I"))
                return std::nullopt;
            auto i_sv = idc.consume_string_view();
            if (i_sv.size() < 32)
                return std::nullopt;
            std::memcpy(si.identity.data(), i_sv.data(), 32);

            // "M" -> mlkem pubkey
            if (!idc.skip_until("M"))
                return std::nullopt;
            auto m_sv = idc.consume_string_view();
            if (m_sv.size() < si.mlkem_pubkey.size())
                return std::nullopt;
            std::memcpy(si.mlkem_pubkey.data(), m_sv.data(), si.mlkem_pubkey.size());

            // "X" -> x25519 pubkey
            if (!idc.skip_until("X"))
                return std::nullopt;
            auto x_sv = idc.consume_string_view();
            if (x_sv.size() < 32)
                return std::nullopt;
            std::memcpy(si.x_pubkey.data(), x_sv.data(), 32);

            // "p" -> pivot hop ID
            if (!idc.skip_until("p"))
                return std::nullopt;
            auto p_sv = idc.consume_string_view();
            if (p_sv.size() < 16)
                return std::nullopt;
            std::memcpy(si.pivot_id.data(), p_sv.data(), 16);

            // "t" -> session tag
            if (!idc.skip_until("t"))
                return std::nullopt;
            auto t_sv = idc.consume_string_view();
            if (t_sv.size() < 4)
                return std::nullopt;
            uint32_t t;
            std::memcpy(&t, t_sv.data(), 4);
            si.tag = uint_to_tag(t);

            // "~" -> signature
            if (!idc.skip_until("~"))
                return std::nullopt;
            auto sig_sv = idc.consume_string_view();
            if (sig_sv.size() < 64)
                return std::nullopt;
            std::memcpy(si.signature.data(), sig_sv.data(), 64);

            // Verify signature over the prefix
            auto inner_str = std::string(inner_sv);
            if (!verify_signature(inner_str, as_uchar(si.identity)))
                return std::nullopt;

            return si;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    // === SessionAccept: BT-encoded with sealed box ===

    std::vector<std::byte> SessionAccept::seal_for(
        const Ed25519PubKey& recipient, const Ed25519SecKey& our_sk) const
    {
        // Build inner BT dict (without signature):
        // {"Y":x25519, "c":mlkem_ct, "t":tag}
        std::string inner_prefix;
        {
            oxenc::bt_dict_producer dp{};
            dp.append("Y", std::string_view{reinterpret_cast<const char*>(x_pubkey.data()), 32});
            dp.append("c", std::string_view{reinterpret_cast<const char*>(mlkem_ciphertext.data()), mlkem_ciphertext.size()});

            uint32_t t = tag_to_uint(tag);
            std::array<char, 4> tag_buf;
            std::memcpy(tag_buf.data(), &t, 4);
            dp.append("t", std::string_view{tag_buf.data(), 4});

            inner_prefix = std::move(dp).str();
        }

        // Remove trailing 'e' for signable prefix
        if (!inner_prefix.empty() && inner_prefix.back() == 'e')
            inner_prefix.pop_back();

        // Sign and append
        auto inner_bt = append_signature(inner_prefix, as_uchar(our_sk));
        auto inner_bytes = to_bytes(inner_bt);

        // Seal
        auto sealed = seal(inner_bytes, recipient);

        // Build outer: {"":"a", "B":<sealed>}
        std::string outer;
        {
            oxenc::bt_dict_producer dp{};
            dp.append("", "a");
            dp.append("B", std::string_view{reinterpret_cast<const char*>(sealed.data()), sealed.size()});
            outer = std::move(dp).str();
        }

        return to_bytes(outer);
    }

    std::optional<SessionAccept> SessionAccept::unseal(
        std::span<const std::byte> bt_outer, const Ed25519PubKey& our_pk, const Ed25519SecKey& our_sk)
    {
        try
        {
            auto sv = to_sv(bt_outer);
            oxenc::bt_dict_consumer dc{sv};

            if (!dc.skip_until(""))
                return std::nullopt;
            auto type = dc.consume_string();
            if (type != "a")
                return std::nullopt;

            if (!dc.skip_until("B"))
                return std::nullopt;
            auto sealed_sv = dc.consume_string_view();
            std::vector<std::byte> sealed_data(
                reinterpret_cast<const std::byte*>(sealed_sv.data()),
                reinterpret_cast<const std::byte*>(sealed_sv.data() + sealed_sv.size()));

            auto inner = sr::crypto::unseal(sealed_data, our_pk, our_sk);
            if (!inner)
                return std::nullopt;

            auto inner_sv = to_sv(*inner);
            oxenc::bt_dict_consumer idc{inner_sv};

            SessionAccept sa;

            // "Y" -> x25519 pubkey
            if (!idc.skip_until("Y"))
                return std::nullopt;
            auto y_sv = idc.consume_string_view();
            if (y_sv.size() < 32)
                return std::nullopt;
            std::memcpy(sa.x_pubkey.data(), y_sv.data(), 32);

            // "c" -> mlkem ciphertext
            if (!idc.skip_until("c"))
                return std::nullopt;
            auto c_sv = idc.consume_string_view();
            if (c_sv.size() < sa.mlkem_ciphertext.size())
                return std::nullopt;
            std::memcpy(sa.mlkem_ciphertext.data(), c_sv.data(), sa.mlkem_ciphertext.size());

            // "t" -> session tag
            if (!idc.skip_until("t"))
                return std::nullopt;
            auto t_sv = idc.consume_string_view();
            if (t_sv.size() < 4)
                return std::nullopt;
            uint32_t t;
            std::memcpy(&t, t_sv.data(), 4);
            sa.tag = uint_to_tag(t);

            // "~" -> signature
            if (!idc.skip_until("~"))
                return std::nullopt;
            auto sig_sv = idc.consume_string_view();
            if (sig_sv.size() < 64)
                return std::nullopt;
            std::memcpy(sa.signature.data(), sig_sv.data(), 64);

            return sa;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    // === Session control messages ===

    std::vector<std::byte> SessionControl::to_bt() const
    {
        std::string buf;
        {
            oxenc::bt_dict_producer dp{};
            dp.append("e", method);
            dp.append("p", std::string_view{reinterpret_cast<const char*>(payload.data()), payload.size()});
            buf = std::move(dp).str();
        }
        return to_bytes(buf);
    }

    std::optional<SessionControl> SessionControl::from_bt(std::span<const std::byte> data)
    {
        try
        {
            auto sv = to_sv(data);
            oxenc::bt_dict_consumer dc{sv};

            SessionControl sc;

            if (!dc.skip_until("e"))
                return std::nullopt;
            sc.method = dc.consume_string();

            if (!dc.skip_until("p"))
                return std::nullopt;
            auto p_sv = dc.consume_string_view();
            sc.payload.assign(
                reinterpret_cast<const std::byte*>(p_sv.data()),
                reinterpret_cast<const std::byte*>(p_sv.data() + p_sv.size()));

            return sc;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

}  // namespace sr::session
