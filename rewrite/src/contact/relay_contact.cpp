#include <sr/contact/relay_contact.hpp>

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
    // Simple serialization: rid || addr_ipv4 || addr_port || version || timestamp
    // This is a simplified format for now.
    // TODO: match upstream BT-encoding exactly for wire compatibility.
    std::vector<std::byte> out;
    out.reserve(32 + 4 + 2 + 3 + 8);

    // RouterID (32 bytes)
    auto pk = _rid.pubkey();
    out.insert(out.end(), pk.begin(), pk.end());

    // Address: IPv4 (4 bytes) + port (2 bytes)
    auto ip_bytes = reinterpret_cast<const std::byte*>(&_addr.ipv4);
    out.insert(out.end(), ip_bytes, ip_bytes + 4);
    auto port_bytes = reinterpret_cast<const std::byte*>(&_addr.port);
    out.insert(out.end(), port_bytes, port_bytes + 2);

    // Version (3 bytes)
    for (auto v : _version)
        out.push_back(static_cast<std::byte>(v));

    // Timestamp (8 bytes, seconds since epoch)
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
        _timestamp.time_since_epoch()).count();
    auto ts_bytes = reinterpret_cast<const std::byte*>(&ts);
    out.insert(out.end(), ts_bytes, ts_bytes + 8);

    return out;
}

// TODO: from_bt() requires BT-encoding library. Stub for now.
std::optional<RelayContact> RelayContact::from_bt(std::span<const std::byte>) {
    return std::nullopt;  // placeholder
}

}  // namespace sr::contact
