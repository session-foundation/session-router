#include <arpa/inet.h>
#include <sodium.h>
#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/bt.hpp>

#include <cstring>

namespace sr::contact
{

    using namespace sr::crypto;
    using namespace sr::encoding;

    RelayContact::RelayContact(
        const RouterID& rid,
        const RelayAddress& addr,
        std::array<uint8_t, 3> version,
        std::chrono::system_clock::time_point timestamp)
        : _rid{rid}, _addr{addr}, _version{version}, _timestamp{timestamp}
    {}

    void RelayContact::sign(const Ed25519SecKey& sk)
    {
        auto data = to_bt_unsigned();
        crypto_sign_detached(
            as_uchar(_sig), nullptr, reinterpret_cast<const unsigned char*>(data.data()), data.size(), as_uchar(sk));
    }

    bool RelayContact::verify() const
    {
        auto data = to_bt_unsigned();
        return crypto_sign_verify_detached(
                   as_uchar(_sig),
                   reinterpret_cast<const unsigned char*>(data.data()),
                   data.size(),
                   as_uchar(_rid.pubkey()))
            == 0;
    }

    bool RelayContact::is_expired(std::chrono::system_clock::time_point now, std::chrono::seconds max_age) const
    {
        return (now - _timestamp) > max_age;
    }

    bool RelayContact::is_outdated(std::chrono::system_clock::time_point now) const
    {
        return (now - _timestamp) > RC_OUTDATED_THRESHOLD;
    }

    std::vector<std::byte> RelayContact::to_bt_unsigned() const
    {
        // BT-encoded dict matching upstream wire format.
        // Keys are in sorted order (bencode requirement).
        // "" < "#" < "4" < "6" < "p" < "t" < "v"
        // "~" is NOT included — added separately for signing.

        std::string buf;
        {
            oxenc::bt_dict_producer dp{};

            // "" -> RC version (only if non-zero)
            if (_rc_version > 0)
                dp.append("", static_cast<int>(_rc_version));

            // "#" -> network ID (only if non-zero)
            if (_network_id != 0)
                dp.append("#", _network_id);

            // "4" -> IPv4 address (4 bytes) + port (2 bytes big-endian)
            std::array<char, 6> addr4_bytes{};
            std::memcpy(addr4_bytes.data(), &_addr.ipv4, 4);
            uint16_t port_be = htons(_addr.port);
            std::memcpy(addr4_bytes.data() + 4, &port_be, 2);
            dp.append("4", std::string_view{addr4_bytes.data(), 6});

            // "6" -> IPv6 address (16 bytes) + port (2 bytes big-endian) [optional]
            if (_ipv6.present)
            {
                std::array<char, 18> addr6_bytes{};
                std::memcpy(addr6_bytes.data(), _ipv6.addr.data(), 16);
                uint16_t port6_be = htons(_ipv6.port);
                std::memcpy(addr6_bytes.data() + 16, &port6_be, 2);
                dp.append("6", std::string_view{addr6_bytes.data(), 18});
            }

            // "p" -> pubkey
            auto& pk = _rid.pubkey();
            dp.append("p", std::string_view{reinterpret_cast<const char*>(pk.data()), 32});

            // "t" -> timestamp
            auto ts = std::chrono::duration_cast<std::chrono::seconds>(_timestamp.time_since_epoch()).count();
            dp.append("t", ts);

            // "v" -> version
            dp.append("v", std::string_view{reinterpret_cast<const char*>(_version.data()), 3});

            buf = std::move(dp).str();
        }

        return to_bytes(buf);
    }

    std::vector<std::byte> RelayContact::to_bt_signed() const
    {
        auto unsigned_data = to_bt_unsigned();
        auto unsigned_str = std::string(
            reinterpret_cast<const char*>(unsigned_data.data()), unsigned_data.size());

        // Remove trailing 'e' to get signable prefix
        if (!unsigned_str.empty() && unsigned_str.back() == 'e')
            unsigned_str.pop_back();

        // Append "~":signature + 'e'
        unsigned_str.append("1:~");
        unsigned_str.append("64:");
        unsigned_str.append(reinterpret_cast<const char*>(_sig.data()), 64);
        unsigned_str.append("e");

        return to_bytes(unsigned_str);
    }

    std::optional<RelayContact> RelayContact::from_bt(std::span<const std::byte> data)
    {
        if (data.size() > RC_MAX_SIZE)
            return std::nullopt;

        try
        {
            auto sv = to_sv(data);
            oxenc::bt_dict_consumer dc{sv};

            RelayContact rc;

            // "" -> RC version (optional)
            std::string empty_key{""};
            if (dc.skip_until(empty_key))
            {
                rc._rc_version = static_cast<uint8_t>(dc.consume_integer<int>());
            }

            // "#" -> network ID (optional)
            if (dc.skip_until("#"))
            {
                rc._network_id = dc.consume_integer<int>();
            }

            // "4" -> IPv4 address (required)
            if (!dc.skip_until("4"))
                return std::nullopt;
            auto addr_sv = dc.consume_string_view();
            if (addr_sv.size() < 6)
                return std::nullopt;
            std::memcpy(&rc._addr.ipv4, addr_sv.data(), 4);
            uint16_t port_be;
            std::memcpy(&port_be, addr_sv.data() + 4, 2);
            rc._addr.port = ntohs(port_be);

            // "6" -> IPv6 address (optional)
            if (dc.skip_until("6"))
            {
                auto addr6_sv = dc.consume_string_view();
                if (addr6_sv.size() >= 18)
                {
                    rc._ipv6.present = true;
                    std::memcpy(rc._ipv6.addr.data(), addr6_sv.data(), 16);
                    uint16_t port6_be;
                    std::memcpy(&port6_be, addr6_sv.data() + 16, 2);
                    rc._ipv6.port = ntohs(port6_be);
                }
            }

            // "p" -> pubkey
            if (!dc.skip_until("p"))
                return std::nullopt;
            auto pk_sv = dc.consume_string_view();
            if (pk_sv.size() < 32)
                return std::nullopt;
            Ed25519PubKey pk;
            std::memcpy(pk.data(), pk_sv.data(), 32);
            rc._rid = RouterID{pk};

            // "t" -> timestamp
            if (!dc.skip_until("t"))
                return std::nullopt;
            auto ts = dc.consume_integer<int64_t>();
            rc._timestamp = std::chrono::system_clock::time_point{std::chrono::seconds{ts}};

            // "v" -> version
            if (!dc.skip_until("v"))
                return std::nullopt;
            auto v_sv = dc.consume_string_view();
            if (v_sv.size() >= 3)
            {
                rc._version[0] = static_cast<uint8_t>(v_sv[0]);
                rc._version[1] = static_cast<uint8_t>(v_sv[1]);
                rc._version[2] = static_cast<uint8_t>(v_sv[2]);
            }

            // "~" -> signature (optional in this context)
            if (dc.skip_until("~"))
            {
                auto sig_sv = dc.consume_string_view();
                if (sig_sv.size() >= 64)
                    std::memcpy(rc._sig.data(), sig_sv.data(), 64);
            }

            return rc;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    // Find the end position of a BT dict starting at data[pos].
    // Returns the position after the closing 'e', or 0 on failure.
    static size_t find_dict_end(std::span<const std::byte> data, size_t pos)
    {
        if (pos >= data.size() || static_cast<char>(data[pos]) != 'd')
            return 0;

        int depth = 0;
        size_t i = pos;
        while (i < data.size())
        {
            char c = static_cast<char>(data[i]);
            if (c == 'd' || c == 'l')
            {
                depth++;
                i++;
            }
            else if (c == 'e')
            {
                depth--;
                i++;
                if (depth == 0)
                    return i;
            }
            else if (c == 'i')
            {
                // Integer: i<digits>e
                i++;
                while (i < data.size() && static_cast<char>(data[i]) != 'e')
                    i++;
                i++;  // skip 'e'
            }
            else if (c >= '0' && c <= '9')
            {
                // String: <len>:<data>
                size_t len = 0;
                while (i < data.size() && static_cast<char>(data[i]) >= '0' && static_cast<char>(data[i]) <= '9')
                {
                    len = len * 10 + (static_cast<char>(data[i]) - '0');
                    i++;
                }
                if (i < data.size() && static_cast<char>(data[i]) == ':')
                    i++;  // skip ':'
                i += len;  // skip string data
            }
            else
            {
                return 0;  // invalid
            }
        }
        return 0;  // unterminated
    }

    std::vector<RelayContact> RelayContact::from_bootstrap(std::span<const std::byte> data)
    {
        std::vector<RelayContact> result;
        if (data.empty())
            return result;

        try
        {
            char first = static_cast<char>(data[0]);

            if (first == 'd')
            {
                // Single RC dict
                auto rc = from_bt(data);
                if (rc)
                    result.push_back(std::move(*rc));
            }
            else if (first == 'l')
            {
                // List of RC dicts — parse manually
                size_t pos = 1;  // skip 'l'
                while (pos < data.size() && static_cast<char>(data[pos]) == 'd')
                {
                    auto end = find_dict_end(data, pos);
                    if (end == 0 || end <= pos)
                        break;

                    auto dict_span = data.subspan(pos, end - pos);
                    auto rc = from_bt(dict_span);
                    if (rc)
                        result.push_back(std::move(*rc));

                    pos = end;
                }
            }
        }
        catch (...)
        {
            // Return whatever we managed to parse
        }

        return result;
    }

}  // namespace sr::contact
