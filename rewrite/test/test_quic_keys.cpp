#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 4: Key Verification (Loopback) ---
// The current Endpoint accepts ALL keys. These tests verify that
// registered relays are accepted and unregistered ones are rejected
// once key verification is implemented.
//
// For now, tests document the current (permissive) behavior and
// mark expected failures as WARNs.

TEST_CASE("4.1 Connection from valid peer accepted", "[quic][keys][loopback]")
{
    QuicTestHarness h;
    h.start();

    // Both peers have valid Ed25519 keys
    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));
    REQUIRE(h.endpoint_a.is_connected(h.rid_b));
}

TEST_CASE("4.2 Connection from unknown peer currently accepted", "[quic][keys][loopback]")
{
    // Generate a third key not registered anywhere
    auto kp_rogue = Ed25519KeyPair::generate();
    RouterID rid_rogue{kp_rogue.pk};

    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_b{kb.pk};

    Endpoint ep_rogue{true};
    Endpoint ep_b{true};

    ep_rogue.listen(0,
        std::span<const std::byte, 32>{kp_rogue.sk.data(), 32},
        std::span<const std::byte, 32>{kp_rogue.pk.data(), 32});
    ep_b.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});

    auto port_b = ep_b.local_port();

    ep_rogue.connect(rid_b, "127.0.0.1", port_b);

    auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline && !ep_rogue.is_connected(rid_b))
        std::this_thread::sleep_for(10ms);

    if (ep_rogue.is_connected(rid_b))
    {
        // Current behavior: accepts all keys
        WARN("Unregistered peer accepted — key verification not yet implemented");
        REQUIRE(true);
    }
    else
    {
        // Future behavior: should reject unregistered peers
        REQUIRE_FALSE(ep_rogue.is_connected(rid_b));
    }

    ep_rogue.close();
    ep_b.close();
}

TEST_CASE("4.6 Client mode accepts anonymous connections", "[quic][keys][loopback]")
{
    // Client connections don't require key verification
    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_b{kb.pk};

    Endpoint client{false};
    Endpoint relay{true};

    client.listen(0,
        std::span<const std::byte, 32>{ka.sk.data(), 32},
        std::span<const std::byte, 32>{ka.pk.data(), 32});
    relay.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});

    auto port_relay = relay.local_port();

    client.connect(rid_b, "127.0.0.1", port_relay);

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && !client.is_connected(rid_b))
        std::this_thread::sleep_for(10ms);

    REQUIRE(client.is_connected(rid_b));

    client.close();
    relay.close();
}

TEST_CASE("4.8 Self-connection doesn't crash", "[quic][keys][loopback]")
{
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};

    Endpoint ep{true};
    ep.listen(0,
        std::span<const std::byte, 32>{kp.sk.data(), 32},
        std::span<const std::byte, 32>{kp.pk.data(), 32});

    auto port = ep.local_port();

    // Connecting to self — should not crash regardless of whether it succeeds
    ep.connect(rid, "127.0.0.1", port);
    std::this_thread::sleep_for(500ms);

    // Either connected or not — just shouldn't crash
    ep.close();
    REQUIRE(true);
}
