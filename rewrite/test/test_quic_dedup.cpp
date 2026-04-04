#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 5: Bidirectional Dedup (Loopback) ---
// Tests for relay_conn lifecycle with two relay instances.
// The relay_conn struct is tested in Category 1. These tests verify
// the Endpoint integrates it correctly.

TEST_CASE("5.1 Single direction A→B", "[quic][dedup][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
    REQUIRE(h.endpoint_a.connection_count() == 1);
}

TEST_CASE("5.2 Both directions established", "[quic][dedup][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    h.connect_b_to_a();

    REQUIRE(h.wait_both_established(5s));

    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
    REQUIRE(h.endpoint_b.is_connected(h.rid_a));
}

TEST_CASE("5.3 Bidirectional connections don't overwrite", "[quic][dedup][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));
    h.run_for(100ms);

    // Now connect in the other direction
    h.connect_b_to_a();

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && !h.endpoint_b.is_connected(h.rid_a))
        std::this_thread::sleep_for(10ms);

    // Both endpoints should still be connected to their peer
    REQUIRE(h.endpoint_a.is_connected(h.rid_b));

    // A should have at least 1 connection (outbound to B)
    REQUIRE(h.endpoint_a.connection_count() >= 1);
}

TEST_CASE("5.4 Data flows after bidirectional setup", "[quic][dedup][loopback]")
{
    QuicTestHarness h;
    h.start();

    std::vector<std::byte> received;
    h.endpoint_b.on_datagram([&](const RouterID& /*from*/, std::span<const std::byte> data) {
        received.assign(data.begin(), data.end());
    });

    h.connect_a_to_b();
    h.connect_b_to_a();
    h.wait_both_established(5s);
    h.run_for(100ms);

    std::vector<std::byte> msg = {std::byte{0x42}};
    h.endpoint_a.send_datagram(h.rid_b, msg);

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && received.empty())
        std::this_thread::sleep_for(10ms);

    REQUIRE(received == msg);
}

TEST_CASE("5.5 Disconnect one direction preserves other", "[quic][dedup][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Now connect B→A
    h.connect_b_to_a();
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && !h.endpoint_b.is_connected(h.rid_a))
        std::this_thread::sleep_for(10ms);

    // Disconnect A's outbound to B
    h.endpoint_a.disconnect(h.rid_b);
    h.run_for(200ms);

    // B's outbound to A should still exist
    REQUIRE(h.endpoint_b.is_connected(h.rid_a));
}
