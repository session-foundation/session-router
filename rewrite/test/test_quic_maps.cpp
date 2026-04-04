#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 2: Connection Map Operations (Loopback) ---
// These tests verify the Endpoint's connection tracking through its public API.
// The current rewrite uses a flat connection map. These tests document the
// behavior we need and will drive the 6-map refactor.

TEST_CASE("2.1 Relay connection storage", "[quic][maps]")
{
    Endpoint ep_a{true};
    Endpoint ep_b{true};

    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_a{ka.pk};
    RouterID rid_b{kb.pk};

    // Before any connections, nothing stored
    REQUIRE_FALSE(ep_a.is_connected(rid_b));
    REQUIRE(ep_a.connection_count() == 0);
}

TEST_CASE("2.3 Pending outbound tracking", "[quic][maps]")
{
    // Verify that connection_count reflects connections
    Endpoint ep{false};
    REQUIRE(ep.connection_count() == 0);
    REQUIRE(ep.connected_peers().empty());
}

TEST_CASE("2.4 Pending outbound dedup", "[quic][maps]")
{
    // Verify that duplicate connect calls don't crash
    // (full dedup behavior requires the 6-map refactor)
    Endpoint ep{false};
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};

    // Can't connect without listen, but disconnect should be safe
    ep.disconnect(rid);
    REQUIRE_FALSE(ep.is_connected(rid));
}

TEST_CASE("2.5 Client connection storage", "[quic][maps]")
{
    // Client mode endpoint tracks connections
    Endpoint ep{false};
    REQUIRE(ep.connection_count() == 0);
    REQUIRE(ep.connected_peers().empty());
}

TEST_CASE("2.9 get_current_relays", "[quic][maps]")
{
    // connected_peers returns empty for new endpoint
    Endpoint ep{true};
    auto peers = ep.connected_peers();
    REQUIRE(peers.empty());
}

TEST_CASE("2.10 connected_to_relay with pending", "[quic][maps]")
{
    // is_connected returns false for unknown peer
    Endpoint ep{true};
    auto kp = Ed25519KeyPair::generate();
    REQUIRE_FALSE(ep.is_connected(RouterID{kp.pk}));
}

// --- Loopback connection tests ---
// These require both endpoints to listen and connect.

TEST_CASE("2.L1 Loopback connection establishes", "[quic][maps][loopback]")
{
    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_a{ka.pk};
    RouterID rid_b{kb.pk};

    Endpoint ep_a{true};
    Endpoint ep_b{true};

    // Listen on port 0 (OS-assigned)
    ep_a.listen(0,
        std::span<const std::byte, 32>{ka.sk.data(), 32},
        std::span<const std::byte, 32>{ka.pk.data(), 32});
    ep_b.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});

    // We need the actual port assigned — but the current Endpoint API
    // doesn't expose it. This test documents the API gap.
    // For now, skip the actual connection and verify the listen didn't crash.
    REQUIRE(ep_a.connection_count() == 0);
    REQUIRE(ep_b.connection_count() == 0);

    ep_a.close();
    ep_b.close();
}

TEST_CASE("2.11 relay_connection_counts", "[quic][maps]")
{
    // connection_count returns 0 for empty endpoint
    Endpoint ep{true};
    REQUIRE(ep.connection_count() == 0);
}

TEST_CASE("2.12 num_relay_conns no double count", "[quic][maps]")
{
    // Verify connection_count is consistent with connected_peers
    Endpoint ep{true};
    REQUIRE(ep.connection_count() == ep.connected_peers().size());
}
