#include <catch2/catch_test_macros.hpp>
#include <sr/crypto/types.hpp>
#include <sr/exit/exit_handler.hpp>

using namespace sr::exit;
using namespace sr::contact;
using namespace sr::crypto;

TEST_CASE("ExitHandler default state", "[exit]")
{
    ExitHandler handler;
    REQUIRE_FALSE(handler.is_enabled());
    REQUIRE(handler.nat_table_size() == 0);
}

TEST_CASE("ExitHandler handle_exit_packet when disabled is no-op", "[exit]")
{
    ExitHandler handler;
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};

    // Minimal IPv4 packet (20 byte header + 4 byte transport)
    std::vector<std::byte> pkt(24, std::byte{0});
    pkt[0] = std::byte{0x45};  // IPv4, IHL=5
    handler.handle_exit_packet(rid, pkt);
    REQUIRE(handler.nat_table_size() == 0);
}

TEST_CASE("ExitHandler NAT entry expiry", "[exit]")
{
    ExitHandler handler;
    auto now = std::chrono::steady_clock::now();
    handler.expire_nat_entries(now);
    REQUIRE(handler.nat_table_size() == 0);
}

TEST_CASE("ExitHandler disable clears state", "[exit]")
{
    ExitHandler handler;
    handler.disable();
    REQUIRE_FALSE(handler.is_enabled());
    REQUIRE(handler.nat_table_size() == 0);
}

TEST_CASE("ExitHandler on_send_back callback registration", "[exit]")
{
    ExitHandler handler;
    bool called = false;
    handler.on_send_back([&](const RouterID&, std::vector<std::byte>) { called = true; });
    // Callback registered but not invoked without enabled + packet
    REQUIRE_FALSE(called);
}

TEST_CASE("RouteManager enable_ip_forwarding needs root", "[exit][route]")
{
    // This will fail without root — that's expected
    bool ok = RouteManager::enable_ip_forwarding();
    // Just verify it doesn't crash; result depends on privileges
    (void)ok;
}

TEST_CASE("RouteManager teardown on inactive is safe", "[exit][route]")
{
    RouteManager rm;
    rm.teardown_routes();     // no crash
    rm.teardown_nat_rules();  // no crash
}
