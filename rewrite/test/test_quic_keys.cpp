#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

#include <unordered_set>

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 4: Key Verification (Loopback) ---

TEST_CASE("4.1 Registered relay accepted", "[quic][keys][loopback]")
{
    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_a{ka.pk};
    RouterID rid_b{kb.pk};

    // Registry: both relays know each other
    std::unordered_set<RouterID> registry{rid_a, rid_b};

    Endpoint ep_a{true};
    Endpoint ep_b{true};

    // B verifies incoming relay keys against registry
    ep_b.set_key_verify([&](const RouterID& rid, std::string_view /*alpn*/) {
        return registry.contains(rid);
    });

    ep_a.listen(0,
        std::span<const std::byte, 32>{ka.sk.data(), 32},
        std::span<const std::byte, 32>{ka.pk.data(), 32});
    ep_b.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});

    auto port_b = ep_b.local_port();
    ep_a.connect(rid_b, "127.0.0.1", port_b);

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && !ep_a.is_connected(rid_b))
        std::this_thread::sleep_for(10ms);

    REQUIRE(ep_a.is_connected(rid_b));

    ep_a.close();
    ep_b.close();
}

TEST_CASE("4.2 Unregistered relay rejected", "[quic][keys][loopback]")
{
    auto kp_rogue = Ed25519KeyPair::generate();
    RouterID rid_rogue{kp_rogue.pk};

    auto kb = Ed25519KeyPair::generate();
    RouterID rid_b{kb.pk};

    // Registry: only B is registered, rogue is NOT
    std::unordered_set<RouterID> registry{rid_b};

    Endpoint ep_rogue{true};
    Endpoint ep_b{true};

    // B rejects unknown relay keys
    ep_b.set_key_verify([&](const RouterID& rid, std::string_view /*alpn*/) {
        return registry.contains(rid);
    });

    ep_rogue.listen(0,
        std::span<const std::byte, 32>{kp_rogue.sk.data(), 32},
        std::span<const std::byte, 32>{kp_rogue.pk.data(), 32});
    ep_b.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});

    auto port_b = ep_b.local_port();
    ep_rogue.connect(rid_b, "127.0.0.1", port_b);

    // Wait — connection should NOT establish
    std::this_thread::sleep_for(2s);

    // Rogue should be rejected — connection should fail or not establish
    // Note: the rogue may think it connected (outbound side doesn't know yet)
    // but B should not have rogue in its connection map
    bool b_has_rogue = ep_b.is_connected(rid_rogue);
    REQUIRE_FALSE(b_has_rogue);

    ep_rogue.close();
    ep_b.close();
}

TEST_CASE("4.3 No key verify callback accepts all", "[quic][keys][loopback]")
{
    // Without set_key_verify, all connections accepted (permissive mode)
    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_b{kb.pk};

    Endpoint ep_a{true};
    Endpoint ep_b{true};
    // NOTE: no set_key_verify on ep_b

    ep_a.listen(0,
        std::span<const std::byte, 32>{ka.sk.data(), 32},
        std::span<const std::byte, 32>{ka.pk.data(), 32});
    ep_b.listen(0,
        std::span<const std::byte, 32>{kb.sk.data(), 32},
        std::span<const std::byte, 32>{kb.pk.data(), 32});

    auto port_b = ep_b.local_port();
    ep_a.connect(rid_b, "127.0.0.1", port_b);

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && !ep_a.is_connected(rid_b))
        std::this_thread::sleep_for(10ms);

    REQUIRE(ep_a.is_connected(rid_b));

    ep_a.close();
    ep_b.close();
}

TEST_CASE("4.6 Client ALPN bypasses key verify", "[quic][keys][loopback]")
{
    auto [ka, kb] = generate_sorted_keypairs();
    RouterID rid_b{kb.pk};

    Endpoint client{false};  // client mode
    Endpoint relay{true};

    // Relay rejects ALL relay keys (very strict)
    relay.set_key_verify([](const RouterID& /*rid*/, std::string_view /*alpn*/) {
        return false;  // reject everything
    });

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

    // Client ALPN should bypass key verification
    REQUIRE(client.is_connected(rid_b));

    client.close();
    relay.close();
}

TEST_CASE("4.8 Self-connection doesn't crash", "[quic][keys][loopback]")
{
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};

    Endpoint ep{true};

    // Self-rejection via key verify
    ep.set_key_verify([&](const RouterID& r, std::string_view /*alpn*/) {
        return r != rid;  // reject self
    });

    ep.listen(0,
        std::span<const std::byte, 32>{kp.sk.data(), 32},
        std::span<const std::byte, 32>{kp.pk.data(), 32});

    auto port = ep.local_port();
    ep.connect(rid, "127.0.0.1", port);
    std::this_thread::sleep_for(500ms);

    ep.close();
    REQUIRE(true);  // no crash = pass
}
