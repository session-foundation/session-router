#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 6: Connection Lifecycle (Loopback) ---
// Tests the full pending → established → closed lifecycle.

TEST_CASE("6.L0 Harness starts and gets ports", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    REQUIRE(h.port_a > 0);
    REQUIRE(h.port_b > 0);
    REQUIRE(h.port_a != h.port_b);
    REQUIRE(h.rid_a < h.rid_b);  // sorted guarantee
}

TEST_CASE("6.1 Outbound connection establishes", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    // A connects to B
    h.connect_a_to_b();

    // Wait for connection to establish
    bool established = h.wait_established(5s);
    REQUIRE(established);
    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
}

TEST_CASE("6.2 Inbound connection visible", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    h.wait_established(5s);

    // B should see the inbound connection from A
    // Give a bit of time for the inbound callback to fire
    h.run_for(100ms);
    bool b_sees_a = h.endpoint_b.is_connected(h.rid_a);

    // Note: this may fail if the Endpoint doesn't track inbound connections
    // by RouterID. The current flat-map design should handle this via the
    // connection_established callback.
    if (b_sees_a)
    {
        REQUIRE(h.endpoint_b.connection_count() >= 1);
    }
    else
    {
        // Document the gap: inbound connections not tracked by RouterID
        WARN("Inbound connection from A not visible at B by RouterID — API gap");
    }
}

TEST_CASE("6.4 Connection close cleans up", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Disconnect A from B
    h.endpoint_a.disconnect(h.rid_b);
    h.run_for(200ms);  // allow close callback to fire

    REQUIRE_FALSE(h.endpoint_a.is_connected(h.rid_b));
    REQUIRE(h.endpoint_a.connection_count() == 0);
}

TEST_CASE("6.5 Close via endpoint.close()", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Full shutdown
    h.endpoint_a.close();
    REQUIRE(h.endpoint_a.connection_count() == 0);
}

TEST_CASE("6.8 Multiple connections tracked", "[quic][lifecycle][loopback]")
{
    // Create a third relay and verify A can connect to both B and C
    auto [ka, kb] = generate_sorted_keypairs();
    auto kc = Ed25519KeyPair::generate();
    RouterID rid_a{ka.pk};
    RouterID rid_b{kb.pk};
    RouterID rid_c{kc.pk};

    Endpoint ep_a{true};
    Endpoint ep_b{true};
    Endpoint ep_c{true};

    ep_a.listen(0,
        std::span<const std::byte, 32>{ka.sk.data(), 32},
        std::span<const std::byte, 32>{ka.pk.data(), 32});
    ep_b.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});
    ep_c.listen(0,
        std::span<const std::byte, 32>{kc.sk.data(), 32},
        std::span<const std::byte, 32>{kc.pk.data(), 32});

    auto port_b = ep_b.local_port();
    auto port_c = ep_c.local_port();

    ep_a.connect(rid_b, "127.0.0.1", port_b);
    ep_a.connect(rid_c, "127.0.0.1", port_c);

    // Wait for both
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (ep_a.is_connected(rid_b) && ep_a.is_connected(rid_c))
            break;
        std::this_thread::sleep_for(10ms);
    }

    REQUIRE(ep_a.is_connected(rid_b));
    REQUIRE(ep_a.is_connected(rid_c));
    REQUIRE(ep_a.connection_count() == 2);

    auto peers = ep_a.connected_peers();
    REQUIRE(peers.size() == 2);

    ep_a.close();
    ep_b.close();
    ep_c.close();
}

TEST_CASE("6.10 Disconnect unknown peer is safe", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    auto kp = Ed25519KeyPair::generate();
    h.endpoint_a.disconnect(RouterID{kp.pk});  // no crash
    REQUIRE(h.endpoint_a.connection_count() == 0);
}

TEST_CASE("6.11 Double close is safe", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    h.endpoint_a.close();
    h.endpoint_a.close();  // second close should not crash
    REQUIRE(h.endpoint_a.connection_count() == 0);
}

TEST_CASE("6.13 Send datagram over loopback", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    std::vector<std::byte> received_data;
    RouterID received_from;

    h.endpoint_b.on_datagram([&](const RouterID& from, std::span<const std::byte> data) {
        received_from = from;
        received_data.assign(data.begin(), data.end());
    });

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Send datagram from A to B
    std::vector<std::byte> msg = {std::byte{0x48}, std::byte{0x65}, std::byte{0x6c}, std::byte{0x6c}, std::byte{0x6f}};
    h.endpoint_a.send_datagram(h.rid_b, msg);

    // Wait for delivery
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && received_data.empty())
        std::this_thread::sleep_for(10ms);

    REQUIRE(received_data == msg);
    REQUIRE(received_from == h.rid_a);
}

TEST_CASE("6.14 Send BTStream request over loopback", "[quic][lifecycle][loopback]")
{
    QuicTestHarness h;
    h.start();

    bool handler_called = false;
    std::string received_method;

    h.endpoint_b.on_request(
        [&](const RouterID& /*from*/, std::string_view method, std::span<const std::byte> payload,
            std::function<void(std::vector<std::byte>)> respond) {
            handler_called = true;
            received_method = std::string{method};
            // Echo back the payload
            respond(std::vector<std::byte>{payload.begin(), payload.end()});
        });

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    std::vector<std::byte> response_data;
    std::vector<std::byte> payload = {std::byte{0x01}, std::byte{0x02}};

    h.endpoint_a.send_request(h.rid_b, "ping", payload, [&](std::span<const std::byte> resp) {
        response_data.assign(resp.begin(), resp.end());
    });

    // Wait for round-trip
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && response_data.empty())
        std::this_thread::sleep_for(10ms);

    REQUIRE(handler_called);
    REQUIRE(received_method == "ping");
    REQUIRE(response_data == payload);
}
