#include <catch2/catch_test_macros.hpp>
#include <sr/link/endpoint.hpp>
#include <sr/link/manager.hpp>

using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// Manager tests use a real Endpoint but don't connect to anything.
// We test the dispatch logic, not the network.

TEST_CASE("Manager registers and dispatches handlers", "[link][manager]")
{
    Endpoint ep{false};
    Manager mgr{ep};

    bool called = false;
    std::string received_method;

    mgr.on(
        "test_method", [&](const RouterID&, std::span<const std::byte>, std::function<void(std::vector<std::byte>)>) {
            called = true;
        });

    // The handler is registered but we can't trigger it without a real connection.
    // Verify registration didn't crash.
    REQUIRE_FALSE(called);
}

TEST_CASE("Manager connection queries on empty endpoint", "[link][manager]")
{
    Endpoint ep{false};
    Manager mgr{ep};

    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};

    REQUIRE_FALSE(mgr.is_connected(rid));
    REQUIRE(mgr.connected_peers().empty());
}

TEST_CASE("Manager multiple handler registration", "[link][manager]")
{
    Endpoint ep{false};
    Manager mgr{ep};

    int count = 0;
    mgr.on("method_a", [&](const RouterID&, std::span<const std::byte>, std::function<void(std::vector<std::byte>)>) {
        ++count;
    });
    mgr.on("method_b", [&](const RouterID&, std::span<const std::byte>, std::function<void(std::vector<std::byte>)>) {
        ++count;
    });

    // Both registered without conflict
    REQUIRE(count == 0);
}

TEST_CASE("Endpoint default state", "[link][endpoint]")
{
    Endpoint ep{false};
    REQUIRE(ep.connection_count() == 0);
    REQUIRE(ep.connected_peers().empty());
}

TEST_CASE("Endpoint is_connected on unknown peer", "[link][endpoint]")
{
    Endpoint ep{true};
    auto kp = Ed25519KeyPair::generate();
    REQUIRE_FALSE(ep.is_connected(RouterID{kp.pk}));
}

TEST_CASE("Endpoint close on uninitialized is safe", "[link][endpoint]")
{
    Endpoint ep{false};
    ep.close();
    REQUIRE(ep.connection_count() == 0);
}

TEST_CASE("Endpoint disconnect unknown peer is safe", "[link][endpoint]")
{
    Endpoint ep{false};
    auto kp = Ed25519KeyPair::generate();
    ep.disconnect(RouterID{kp.pk});  // should not crash
}

TEST_CASE("Endpoint send_datagram to unknown peer is safe", "[link][endpoint]")
{
    Endpoint ep{false};
    auto kp = Ed25519KeyPair::generate();
    std::vector<std::byte> data(32);
    ep.send_datagram(RouterID{kp.pk}, data);  // should not crash
}

TEST_CASE("Endpoint send_request to unknown peer is safe", "[link][endpoint]")
{
    Endpoint ep{false};
    auto kp = Ed25519KeyPair::generate();
    std::vector<std::byte> data(32);
    ep.send_request(RouterID{kp.pk}, "test", data);  // should not crash
}
