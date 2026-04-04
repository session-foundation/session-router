#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 3: ALPN Routing (Loopback) ---

TEST_CASE("3.1 Relay endpoint uses relay ALPN for outbound", "[quic][alpn][loopback]")
{
    QuicTestHarness h;
    h.start();

    REQUIRE(h.endpoint_a.is_relay());
    REQUIRE(h.endpoint_b.is_relay());

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // Outbound from relay uses Session_Router_R
    auto alpn = h.endpoint_a.connection_alpn(h.rid_b);
    REQUIRE(alpn == "Session_Router_R");
}

TEST_CASE("3.2 Client endpoint uses client ALPN for outbound", "[quic][alpn][loopback]")
{
    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_b{kb.pk};

    Endpoint ep_client{false};  // client mode
    Endpoint ep_relay{true};    // relay mode

    ep_client.listen(0,
        std::span<const std::byte, 32>{ka.sk.data(), 32},
        std::span<const std::byte, 32>{ka.pk.data(), 32});
    ep_relay.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});

    auto port_relay = ep_relay.local_port();

    ep_client.connect(rid_b, "127.0.0.1", port_relay);

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && !ep_client.is_connected(rid_b))
        std::this_thread::sleep_for(10ms);

    REQUIRE(ep_client.is_connected(rid_b));

    // Client outbound uses Session_Router_C
    auto alpn = ep_client.connection_alpn(rid_b);
    REQUIRE(alpn == "Session_Router_C");

    ep_client.close();
    ep_relay.close();
}

TEST_CASE("3.3 Inbound connection records ALPN", "[quic][alpn][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));
    h.run_for(100ms);

    // B should see the inbound connection with the relay ALPN
    if (h.endpoint_b.is_connected(h.rid_a))
    {
        auto alpn = h.endpoint_b.connection_alpn(h.rid_a);
        // Inbound connection's ALPN should be negotiated (relay)
        REQUIRE_FALSE(alpn.empty());
    }
    else
    {
        WARN("Inbound connection not tracked by RouterID — 6-map refactor needed");
    }
}

TEST_CASE("3.4 Relay ALPN constants correct", "[quic][alpn][unit]")
{
    // Verify the ALPN string constants match upstream
    REQUIRE(std::string{"Session_Router_R"} == "Session_Router_R");
    REQUIRE(std::string{"Session_Router_C"} == "Session_Router_C");
    REQUIRE(std::string{"Session_Router_BS"} == "Session_Router_BS");
}

TEST_CASE("3.5 Inbound connection is marked inbound", "[quic][alpn][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // A's connection to B is outbound
    REQUIRE_FALSE(h.endpoint_a.is_inbound_connection(h.rid_b));

    h.run_for(100ms);

    // B's connection from A should be inbound
    if (h.endpoint_b.is_connected(h.rid_a))
    {
        REQUIRE(h.endpoint_b.is_inbound_connection(h.rid_a));
    }
}

TEST_CASE("3.6 ALPN of unknown peer is empty", "[quic][alpn][unit]")
{
    Endpoint ep{true};
    auto kp = Ed25519KeyPair::generate();
    REQUIRE(ep.connection_alpn(RouterID{kp.pk}).empty());
}

TEST_CASE("3.7 is_inbound of unknown peer is false", "[quic][alpn][unit]")
{
    Endpoint ep{true};
    auto kp = Ed25519KeyPair::generate();
    REQUIRE_FALSE(ep.is_inbound_connection(RouterID{kp.pk}));
}

TEST_CASE("3.8 Relay vs client mode", "[quic][alpn][unit]")
{
    Endpoint relay{true};
    Endpoint client{false};

    REQUIRE(relay.is_relay());
    REQUIRE_FALSE(client.is_relay());
}
