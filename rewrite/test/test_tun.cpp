#include <catch2/catch_test_macros.hpp>
#include <sr/node/tun.hpp>

using namespace sr::node;

TEST_CASE("TunDevice default state", "[node][tun]")
{
    TunDevice tun;
    REQUIRE_FALSE(tun.is_open());
    REQUIRE(tun.fd() < 0);
    REQUIRE(tun.name().empty());
}

TEST_CASE("TunDevice close on unopened is safe", "[node][tun]")
{
    TunDevice tun;
    tun.close();  // should not crash
    REQUIRE_FALSE(tun.is_open());
}

TEST_CASE("TunDevice write_packet on closed returns false", "[node][tun]")
{
    TunDevice tun;
    std::vector<std::byte> pkt(64);
    REQUIRE_FALSE(tun.write_packet(pkt));
}

TEST_CASE("TunDevice read_packet on closed returns empty", "[node][tun]")
{
    TunDevice tun;
    auto pkt = tun.read_packet();
    REQUIRE(pkt.empty());
}

TEST_CASE("TunDevice write empty packet returns false", "[node][tun]")
{
    TunDevice tun;
    REQUIRE_FALSE(tun.write_packet({}));
}

// Note: actual TUN open/read/write tests require root or CAP_NET_ADMIN.
// These tests verify the interface behaves correctly in unprivileged mode.
TEST_CASE("TunDevice open without privileges fails gracefully", "[node][tun]")
{
    TunDevice tun;
    // This will fail unless running as root — that's expected
    bool opened = tun.open("srtest0", "10.99.99.1", 24);
    if (!opened)
    {
        REQUIRE_FALSE(tun.is_open());
        REQUIRE(tun.fd() < 0);
    }
    else
    {
        // Running as root — verify it works
        REQUIRE(tun.is_open());
        REQUIRE(tun.fd() >= 0);
        REQUIRE_FALSE(tun.name().empty());
        tun.close();
    }
}
