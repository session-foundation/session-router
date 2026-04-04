#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

#include <atomic>
#include <thread>

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 11: Threading (Loopback) ---

TEST_CASE("11.1 Connection callback fires correctly", "[quic][threading][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // The connection was established via the QUIC network loop callback
    // and the state is now visible in the main thread
    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
    REQUIRE(h.endpoint_a.connection_count() == 1);
}

TEST_CASE("11.2 Query during active connections", "[quic][threading][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Multiple queries shouldn't corrupt state
    for (int i = 0; i < 100; ++i)
    {
        REQUIRE(h.endpoint_a.is_connected(h.rid_b));
        REQUIRE(h.endpoint_a.connection_count() == 1);
        auto peers = h.endpoint_a.connected_peers();
        REQUIRE(peers.size() == 1);
    }
}

TEST_CASE("11.3 Concurrent send and query", "[quic][threading][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.endpoint_b.on_datagram([](const RouterID& /*from*/, std::span<const std::byte> /*data*/) {
        // Just consume
    });

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Send datagrams while querying state
    std::atomic<bool> done{false};
    std::thread sender([&] {
        std::vector<std::byte> data(64, std::byte{0x42});
        for (int i = 0; i < 50 && !done; ++i)
        {
            h.endpoint_a.send_datagram(h.rid_b, data);
            std::this_thread::sleep_for(1ms);
        }
        done = true;
    });

    // Query while sending
    while (!done)
    {
        [[maybe_unused]] auto count = h.endpoint_a.connection_count();
        [[maybe_unused]] auto connected = h.endpoint_a.is_connected(h.rid_b);
        std::this_thread::sleep_for(1ms);
    }

    sender.join();
    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
}

TEST_CASE("11.4 Connect and disconnect stress", "[quic][threading][loopback]")
{
    // Rapidly connect and disconnect without crashing
    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_b{kb.pk};

    Endpoint ep_a{true};
    Endpoint ep_b{true};

    ep_a.listen(0,
        std::span<const std::byte, 32>{ka.sk.data(), 32},
        std::span<const std::byte, 32>{ka.pk.data(), 32});
    ep_b.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});

    auto port_b = ep_b.local_port();

    for (int i = 0; i < 3; ++i)
    {
        ep_a.connect(rid_b, "127.0.0.1", port_b);
        std::this_thread::sleep_for(100ms);
        ep_a.disconnect(rid_b);
        std::this_thread::sleep_for(50ms);
    }

    ep_a.close();
    ep_b.close();
    REQUIRE(ep_a.connection_count() == 0);
}
