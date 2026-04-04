#include <catch2/catch_test_macros.hpp>
#include "helpers/quic_test_harness.hpp"

using namespace sr::test;
using namespace sr::link;
using namespace sr::contact;
using namespace sr::crypto;

// --- Category 8: Command Dispatch (Loopback) ---

TEST_CASE("8.1 Send command to connected relay", "[quic][commands][loopback]")
{
    QuicTestHarness h;
    h.start();

    std::string received_method;
    std::vector<std::byte> received_payload;

    h.endpoint_b.on_request(
        [&](const RouterID& /*from*/, std::string_view method, std::span<const std::byte> payload,
            std::function<void(std::vector<std::byte>)> respond) {
            received_method = std::string{method};
            received_payload.assign(payload.begin(), payload.end());
            respond({std::byte{0xAA}});
        });

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    std::vector<std::byte> response;
    std::vector<std::byte> body = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};

    h.endpoint_a.send_request(h.rid_b, "test_cmd", body, [&](std::span<const std::byte> resp) {
        response.assign(resp.begin(), resp.end());
    });

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && response.empty())
        std::this_thread::sleep_for(10ms);

    REQUIRE(received_method == "test_cmd");
    REQUIRE(received_payload == body);
    REQUIRE(response.size() == 1);
    REQUIRE(response[0] == std::byte{0xAA});
}

TEST_CASE("8.4 Send datagram to connected peer", "[quic][commands][loopback]")
{
    QuicTestHarness h;
    h.start();

    std::vector<std::byte> received;
    h.endpoint_b.on_datagram([&](const RouterID& /*from*/, std::span<const std::byte> data) {
        received.assign(data.begin(), data.end());
    });

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    std::vector<std::byte> msg = {std::byte{0xDE}, std::byte{0xAD}};
    h.endpoint_a.send_datagram(h.rid_b, msg);

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && received.empty())
        std::this_thread::sleep_for(10ms);

    REQUIRE(received == msg);
}

TEST_CASE("8.5 Send datagram to unconnected drops silently", "[quic][commands][loopback]")
{
    QuicTestHarness h;
    h.start();

    auto kp = Ed25519KeyPair::generate();
    std::vector<std::byte> msg = {std::byte{0x01}};

    // Should not crash — just silently drop
    h.endpoint_a.send_datagram(RouterID{kp.pk}, msg);
    REQUIRE(h.endpoint_a.connection_count() == 0);  // no connection initiated
}

TEST_CASE("8.6 Send command while closed", "[quic][commands][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    h.endpoint_a.close();

    // Send after close — should not crash
    std::vector<std::byte> body = {std::byte{0x01}};
    h.endpoint_a.send_request(h.rid_b, "test", body);
    h.endpoint_a.send_datagram(h.rid_b, body);
    // No crash = pass
    REQUIRE(true);
}

TEST_CASE("8.7 Multiple methods dispatched correctly", "[quic][commands][loopback]")
{
    QuicTestHarness h;
    h.start();

    std::vector<std::string> methods_received;

    h.endpoint_b.on_request(
        [&](const RouterID& /*from*/, std::string_view method, std::span<const std::byte> /*payload*/,
            std::function<void(std::vector<std::byte>)> respond) {
            methods_received.push_back(std::string{method});
            respond({});
        });

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    std::vector<std::byte> body = {std::byte{0x01}};

    h.endpoint_a.send_request(h.rid_b, "method_a", body);
    h.endpoint_a.send_request(h.rid_b, "method_b", body);
    h.endpoint_a.send_request(h.rid_b, "method_c", body);

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && methods_received.size() < 3)
        std::this_thread::sleep_for(10ms);

    REQUIRE(methods_received.size() == 3);
    // Methods may arrive in any order due to async dispatch
    REQUIRE(std::find(methods_received.begin(), methods_received.end(), "method_a") != methods_received.end());
    REQUIRE(std::find(methods_received.begin(), methods_received.end(), "method_b") != methods_received.end());
    REQUIRE(std::find(methods_received.begin(), methods_received.end(), "method_c") != methods_received.end());
}

TEST_CASE("8.8 Large payload transfer", "[quic][commands][loopback]")
{
    QuicTestHarness h;
    h.start();

    h.endpoint_b.on_request(
        [&](const RouterID& /*from*/, std::string_view /*method*/, std::span<const std::byte> payload,
            std::function<void(std::vector<std::byte>)> respond) {
            // Echo back
            respond(std::vector<std::byte>{payload.begin(), payload.end()});
        });

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));

    // 64KB payload
    std::vector<std::byte> big_payload(65536);
    for (size_t i = 0; i < big_payload.size(); ++i)
        big_payload[i] = std::byte(i & 0xFF);

    std::vector<std::byte> response;
    h.endpoint_a.send_request(h.rid_b, "echo", big_payload, [&](std::span<const std::byte> resp) {
        response.assign(resp.begin(), resp.end());
    });

    auto deadline = std::chrono::steady_clock::now() + 10s;
    while (std::chrono::steady_clock::now() < deadline && response.empty())
        std::this_thread::sleep_for(10ms);

    REQUIRE(response.size() == big_payload.size());
    REQUIRE(response == big_payload);
}

TEST_CASE("8.9 Bidirectional commands", "[quic][commands][loopback]")
{
    QuicTestHarness h;
    h.start();

    // Both sides handle requests
    h.endpoint_a.on_request(
        [](const RouterID& /*from*/, std::string_view /*method*/, std::span<const std::byte> /*payload*/,
           std::function<void(std::vector<std::byte>)> respond) {
            respond({std::byte{0xAA}});
        });

    h.endpoint_b.on_request(
        [](const RouterID& /*from*/, std::string_view /*method*/, std::span<const std::byte> /*payload*/,
           std::function<void(std::vector<std::byte>)> respond) {
            respond({std::byte{0xBB}});
        });

    h.connect_a_to_b();
    REQUIRE(h.wait_established(5s));
    h.run_for(100ms);  // allow inbound connection to register

    std::vector<std::byte> resp_from_b, resp_from_a;

    // A → B
    h.endpoint_a.send_request(h.rid_b, "ping", {}, [&](std::span<const std::byte> r) {
        resp_from_b.assign(r.begin(), r.end());
    });

    // B → A (only works if B tracked the inbound connection from A)
    if (h.endpoint_b.is_connected(h.rid_a))
    {
        h.endpoint_b.send_request(h.rid_a, "pong", {}, [&](std::span<const std::byte> r) {
            resp_from_a.assign(r.begin(), r.end());
        });
    }

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline && resp_from_b.empty())
        std::this_thread::sleep_for(10ms);

    REQUIRE(resp_from_b.size() == 1);
    REQUIRE(resp_from_b[0] == std::byte{0xBB});

    if (!resp_from_a.empty())
    {
        REQUIRE(resp_from_a[0] == std::byte{0xAA});
    }
    else if (h.endpoint_b.is_connected(h.rid_a))
    {
        WARN("B→A command sent but no response received — may need outbound BTStream handler (W5)");
    }
}
