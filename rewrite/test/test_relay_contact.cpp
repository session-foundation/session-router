#include <catch2/catch_test_macros.hpp>
#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::contact;
using namespace sr::crypto;

static RelayContact make_rc(const Ed25519KeyPair& kp)
{
    RouterID rid{kp.pk};
    RelayAddress addr{0x0100007F, 1090};  // 127.0.0.1:1090
    auto now = std::chrono::system_clock::now();
    RelayContact rc{rid, addr, {0, 10, 0}, now};
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
    // Signature was made with kp1, but RC claims kp1's RouterID.
    // Verification should pass.
    REQUIRE(rc.verify());

    // If we construct with kp2's RouterID but sign with kp1, verify fails
    RouterID rid2{kp2.pk};
    RelayAddress addr{0x0100007F, 1090};
    auto now = std::chrono::system_clock::now();
    RelayContact bad_rc{rid2, addr, {0, 10, 0}, now};
    bad_rc.sign(kp1.sk);  // signed with wrong key
    REQUIRE_FALSE(bad_rc.verify());
}

TEST_CASE("RelayContact expiry", "[contact][relay_contact]")
{
    auto kp = Ed25519KeyPair::generate();
    auto old_time = std::chrono::system_clock::now() - std::chrono::hours(2);
    RouterID rid{kp.pk};
    RelayAddress addr{0x0100007F, 1090};
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
