#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/bt.hpp>

#include <arpa/inet.h>
#include <cstring>
#include <sodium.h>

namespace sr::contact {

using namespace sr::crypto;

RelayContact::RelayContact(
    const RouterID& rid,
    const RelayAddress& addr,
    std::array<uint8_t, 3> version,
    std::chrono::system_clock::time_point timestamp)
    : _rid{rid}, _addr{addr}, _version{version}, _timestamp{timestamp} {}

void RelayContact::sign(const Ed25519SecKey& sk) {
    auto data = to_bt_unsigned();
    crypto_sign_detached(
        as_uchar(_sig),
        nullptr,
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(),
        as_uchar(sk));
}

bool RelayContact::verify() const {
    auto data = to_bt_unsigned();
    return crypto_sign_verify_detached(
        as_uchar(_sig),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(),
        as_uchar(_rid.pubkey())) == 0;
}

bool RelayContact::is_expired(
    std::chrono::system_clock::time_point now,
    std::chrono::seconds max_age) const
{
    return (now - _timestamp) > max_age;
}

std::vector<std::byte> RelayContact::to_bt_unsigned() const {
    // BT-encoded dict matching upstream wire format:
    // "4" -> 6 bytes (IPv4:port, network byte order)
    // "p" -> 32 bytes (Ed25519 pubkey)
    // "t" -> int64 (unix timestamp)
    // "v" -> 3 bytes (version major.minor.patch)
    // Note: "~" (signature) is NOT included — added separately

    std::string buf;
    {
        oxenc::bt_dict_producer dp{};

        // "4" -> IPv4 address (4 bytes) + port (2 bytes big-endian)
        std::array<char, 6> addr_bytes{};
        std::memcpy(addr_bytes.data(), &_addr.ipv4, 4);
        uint16_t port_be = htons(_addr.port);
        std::memcpy(addr_bytes.data() + 4, &port_be, 2);
        dp.append("4", std::string_view{addr_bytes.data(), 6});

        // "p" -> pubkey
        auto& pk = _rid.pubkey();
        dp.append("p", std::string_view{reinterpret_cast<const char*>(pk.data()), 32});

        // "t" -> timestamp
        auto ts = std::chrono::duration_cast<std::chrono::seconds>(
            _timestamp.time_since_epoch()).count();
        dp.append("t", ts);

        // "v" -> version
        dp.append("v", std::string_view{
            reinterpret_cast<const char*>(_version.data()), 3});

        buf = std::move(dp).str();
    }

    return sr::bt::to_bytes(buf);
}

std::optional<RelayContact> RelayContact::from_bt(std::span<const std::byte> data) {
    try {
        auto sv = sr::bt::to_sv(data);
        oxenc::bt_dict_consumer dc{sv};

        RelayContact rc;

        // "4" -> address
        if (!dc.skip_until("4"))
            return std::nullopt;
        auto addr_sv = dc.consume_string_view();
        if (addr_sv.size() < 6)
            return std::nullopt;
        std::memcpy(&rc._addr.ipv4, addr_sv.data(), 4);
        uint16_t port_be;
        std::memcpy(&port_be, addr_sv.data() + 4, 2);
        rc._addr.port = ntohs(port_be);

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
        if (v_sv.size() >= 3) {
            rc._version[0] = static_cast<uint8_t>(v_sv[0]);
            rc._version[1] = static_cast<uint8_t>(v_sv[1]);
            rc._version[2] = static_cast<uint8_t>(v_sv[2]);
        }

        // "~" -> signature (optional in this context)
        if (dc.skip_until("~")) {
            auto sig_sv = dc.consume_string_view();
            if (sig_sv.size() >= 64)
                std::memcpy(rc._sig.data(), sig_sv.data(), 64);
        }

        return rc;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace sr::contact
