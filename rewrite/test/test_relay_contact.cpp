#include <arpa/inet.h>
#include <catch2/catch_test_macros.hpp>
#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::contact;
using namespace sr::crypto;

static RelayContact make_rc(const Ed25519KeyPair& kp)
{
    RouterID rid{kp.pk};
    RelayAddress addr{htonl(0x7F000001), 1090};  // 127.0.0.1:1090
    auto now = std::chrono::system_clock::now();
    auto now_s = std::chrono::time_point_cast<std::chrono::seconds>(now);
    RelayContact rc{rid, addr, {0, 10, 0}, now_s};
    rc.sign(kp.sk);
    return rc;
}

TEST_CASE("RelayContact sign and verify", "[contact][relay_contact]")
{
    auto kp = Ed25519KeyPair::generate();
    auto rc = make_rc(kp);
    REQUIRE(rc.verify());
}

TEST_CASE("RelayContact wrong key fails verify", "[contact][relay_contact]")
{
    auto kp1 = Ed25519KeyPair::generate();
    auto kp2 = Ed25519KeyPair::generate();

    auto rc = make_rc(kp1);
    REQUIRE(rc.verify());

    // If we construct with kp2's RouterID but sign with kp1, verify fails
    RouterID rid2{kp2.pk};
    RelayAddress addr{htonl(0x7F000001), 1090};
    auto now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
    RelayContact bad_rc{rid2, addr, {0, 10, 0}, now};
    bad_rc.sign(kp1.sk);  // signed with wrong key
    REQUIRE_FALSE(bad_rc.verify());
}

TEST_CASE("RelayContact expiry", "[contact][relay_contact]")
{
    auto kp = Ed25519KeyPair::generate();
    auto old_time = std::chrono::system_clock::now() - std::chrono::hours(2);
    RouterID rid{kp.pk};
    RelayAddress addr{htonl(0x7F000001), 1090};
    RelayContact rc{rid, addr, {0, 10, 0}, old_time};

    REQUIRE(rc.is_expired(std::chrono::system_clock::now()));
    REQUIRE_FALSE(rc.is_expired(std::chrono::system_clock::now(), std::chrono::hours(3)));
}

TEST_CASE("RelayContact accessors", "[contact][relay_contact]")
{
    auto kp = Ed25519KeyPair::generate();
    auto rc = make_rc(kp);

    REQUIRE(rc.router_id() == RouterID{kp.pk});
    REQUIRE(rc.address().port == 1090);
    REQUIRE(rc.version() == std::array<uint8_t, 3>{0, 10, 0});
}

TEST_CASE("RelayContact IPv6 support", "[contact][relay_contact]")
{
    auto kp = Ed25519KeyPair::generate();
    auto rc = make_rc(kp);

    IPv6Address v6;
    v6.present = true;
    // ::1 (loopback)
    v6.addr[15] = 1;
    v6.port = 2090;
    rc.set_ipv6(v6);

    REQUIRE(rc.ipv6().present);
    REQUIRE(rc.ipv6().port == 2090);
    REQUIRE(rc.ipv6().addr[15] == 1);
}

TEST_CASE("RelayContact network ID", "[contact][relay_contact]")
{
    auto kp = Ed25519KeyPair::generate();
    auto rc = make_rc(kp);

    REQUIRE(rc.network_id() == 0);  // mainnet default
    rc.set_network_id(1);           // testnet
    REQUIRE(rc.network_id() == 1);
}

TEST_CASE("RelayContact RC version", "[contact][relay_contact]")
{
    auto kp = Ed25519KeyPair::generate();
    auto rc = make_rc(kp);

    REQUIRE(rc.rc_version() == 0);
    rc.set_rc_version(1);
    REQUIRE(rc.rc_version() == 1);
}

TEST_CASE("RelayContact BT round-trip with IPv6 and netid", "[contact][relay_contact]")
{
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};
    RelayAddress addr{htonl(0x7F000001), 1090};
    auto now_s = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());

    RelayContact rc{rid, addr, {1, 2, 3}, now_s};
    rc.set_network_id(1);

    IPv6Address v6;
    v6.present = true;
    v6.addr[0] = 0xFE;
    v6.addr[1] = 0x80;
    v6.addr[15] = 1;
    v6.port = 3090;
    rc.set_ipv6(v6);
    rc.sign(kp.sk);

    auto bt_data = rc.to_bt_unsigned();
    REQUIRE(bt_data.size() > 0);

    auto parsed = RelayContact::from_bt(bt_data);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->router_id() == rid);
    REQUIRE(parsed->address().port == 1090);
    REQUIRE(parsed->version() == std::array<uint8_t, 3>{1, 2, 3});
    REQUIRE(parsed->network_id() == 1);
    REQUIRE(parsed->ipv6().present);
    REQUIRE(parsed->ipv6().port == 3090);
    REQUIRE(parsed->ipv6().addr[0] == 0xFE);
    REQUIRE(parsed->timestamp() == now_s);
}

TEST_CASE("RelayContact bootstrap single dict", "[contact][relay_contact][bootstrap]")
{
    auto kp = Ed25519KeyPair::generate();
    auto rc = make_rc(kp);
    auto bt = rc.to_bt_signed();

    auto result = RelayContact::from_bootstrap(bt);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].router_id() == rc.router_id());
}

TEST_CASE("RelayContact from_bt with invalid data returns nullopt", "[contact][relay_contact]")
{
    std::vector<std::byte> garbage(10);
    randombytes_buf(garbage.data(), garbage.size());
    auto parsed = RelayContact::from_bt(garbage);
    REQUIRE_FALSE(parsed.has_value());
}

TEST_CASE("RelayContact from_bt with empty data returns nullopt", "[contact][relay_contact]")
{
    auto parsed = RelayContact::from_bt({});
    REQUIRE_FALSE(parsed.has_value());
}

TEST_CASE("RelayContact RC_MAX_SIZE enforcement", "[contact][relay_contact]")
{
    std::vector<std::byte> oversized(RC_MAX_SIZE + 1, std::byte{'d'});
    auto parsed = RelayContact::from_bt(oversized);
    REQUIRE_FALSE(parsed.has_value());
}
