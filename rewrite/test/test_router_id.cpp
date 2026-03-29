#include <catch2/catch_test_macros.hpp>
#include <sr/contact/router_id.hpp>
#include <sr/crypto/types.hpp>

#include <unordered_set>

using namespace sr::contact;
using namespace sr::crypto;

TEST_CASE("RouterID from Ed25519 pubkey", "[contact][router_id]")
{
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};
    REQUIRE(rid.pubkey() == kp.pk);
}

TEST_CASE("RouterID hex round-trip", "[contact][router_id]")
{
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};
    auto hex = rid.to_string();
    REQUIRE(hex.size() == 64);
    auto rid2 = RouterID::from_string(hex);
    REQUIRE(rid == rid2);
}

TEST_CASE("RouterID comparison", "[contact][router_id]")
{
    auto kp1 = Ed25519KeyPair::generate();
    auto kp2 = Ed25519KeyPair::generate();
    RouterID r1{kp1.pk}, r2{kp2.pk}, r1b{kp1.pk};
    REQUIRE(r1 == r1b);
    REQUIRE(r1 != r2);
}

TEST_CASE("RouterID hash works in unordered_set", "[contact][router_id]")
{
    auto kp1 = Ed25519KeyPair::generate();
    auto kp2 = Ed25519KeyPair::generate();
    std::unordered_set<RouterID> s;
    s.insert(RouterID{kp1.pk});
    s.insert(RouterID{kp2.pk});
    s.insert(RouterID{kp1.pk});  // duplicate
    REQUIRE(s.size() == 2);
}

TEST_CASE("RouterID invalid hex throws", "[contact][router_id]")
{
    REQUIRE_THROWS(RouterID::from_string("short"));
    REQUIRE_THROWS(RouterID::from_string(""));
}
