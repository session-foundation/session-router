#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 10: 0-RTT (Loopback) ---
// 0-RTT requires TLS session ticket storage and retrieval.
// The upstream stores tickets in NodeDB. Our rewrite doesn't have
// this infrastructure yet. These tests document the requirements.

TEST_CASE("10.1 First connection establishes normally", "[quic][0rtt][loopback]")
{
    // Baseline: first connection requires full handshake
    QuicTestHarness h;
    h.start();

    auto t0 = std::chrono::steady_clock::now();
    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));
    auto t1 = std::chrono::steady_clock::now();

    auto handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    // Just verify it connected — handshake time is a baseline
    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
    REQUIRE(handshake_ms < 5000);  // sanity check — must complete within timeout
}

TEST_CASE("10.2 Reconnection after disconnect", "[quic][0rtt][loopback]")
{
    QuicTestHarness h;
    h.start();

    // First connection
    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Disconnect
    h.endpoint_a.disconnect(h.rid_b);
    h.run_for(200ms);
    REQUIRE_FALSE(h.endpoint_a.is_connected(h.rid_b));

    // Reconnect — should work (0-RTT would make this faster)
    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));
    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
}

TEST_CASE("10.3 Multiple reconnections stable", "[quic][0rtt][loopback]")
{
    QuicTestHarness h;
    h.start();

    for (int i = 0; i < 3; ++i)
    {
        h.connect_a_to_b();
        REQUIRE(h.wait_established(5s));
        REQUIRE(h.endpoint_a.is_connected(h.rid_b));

        h.endpoint_a.disconnect(h.rid_b);
        h.run_for(200ms);
    }

    // Final connection
    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));
    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
}
