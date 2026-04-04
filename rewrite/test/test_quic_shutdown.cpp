#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 9: Shutdown and Safety (Loopback) ---

TEST_CASE("9.1 Ordered shutdown clears all connections", "[quic][shutdown][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));
    REQUIRE(h.endpoint_a.connection_count() >= 1);

    h.endpoint_a.close();
    REQUIRE(h.endpoint_a.connection_count() == 0);
    REQUIRE(h.endpoint_a.connected_peers().empty());
}

TEST_CASE("9.2 Double stop is safe", "[quic][shutdown][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    h.endpoint_a.close();
    h.endpoint_a.close();  // must not crash
    REQUIRE(h.endpoint_a.connection_count() == 0);
}

TEST_CASE("9.3 Close with pending operations", "[quic][shutdown][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Send some data, then immediately close
    std::vector<std::byte> data(1024, std::byte{0xFF});
    h.endpoint_a.send_datagram(h.rid_b, data);
    h.endpoint_a.send_request(h.rid_b, "test", data);

    // Close while data may be in flight
    h.endpoint_a.close();
    REQUIRE(h.endpoint_a.connection_count() == 0);
}

TEST_CASE("9.4 Uninitialized endpoint close is safe", "[quic][shutdown][loopback]")
{
    // Endpoint created but never listen()'d
    Endpoint ep{false};
    ep.close();  // must not crash
    REQUIRE(ep.connection_count() == 0);
}

TEST_CASE("9.5 Destructor handles cleanup", "[quic][shutdown][loopback]")
{
    {
        QuicTestHarness h;
        h.start();
        h.connect_a_to_b();
        h.wait_established(5s);
        // Destructor fires here — should clean up without crash
    }
    // If we got here, destructor didn't crash
    REQUIRE(true);
}

TEST_CASE("9.6 Rapid create-connect-destroy cycle", "[quic][shutdown][loopback]")
{
    // Stress test: rapidly create, connect, and destroy endpoints
    for (int i = 0; i < 5; ++i)
    {
        QuicTestHarness h;
        h.start();
        h.connect_a_to_b();
        // Don't wait for establishment — destroy immediately
    }
    // No crash = pass
    REQUIRE(true);
}
