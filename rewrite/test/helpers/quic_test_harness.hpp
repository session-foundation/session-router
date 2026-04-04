#pragma once

// Test harness for QUIC loopback tests (Categories 2-11).
// Creates two relay Endpoint instances on localhost with real QUIC connections.
//
// Design requirements from AAA_1281:
// - MockJobQueue must execute call_get inline when inside loop (W1)
// - Port allocation via localhost:0 (OS-assigned)
// - Guarantee: relay_a.rid < relay_b.rid (for winner selection)
// - Both relays registered in each other's MockNodeDB

#include <sr/contact/router_id.hpp>
#include <sr/crypto/types.hpp>
#include <sr/link/endpoint.hpp>
#include <sr/link/relay_conn.hpp>

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std::literals;

namespace sr::test
{
    using namespace sr::contact;
    using namespace sr::crypto;

    // Generate two Ed25519 keypairs, sorted so kp_a.pk < kp_b.pk
    inline std::pair<Ed25519KeyPair, Ed25519KeyPair> generate_sorted_keypairs()
    {
        auto a = Ed25519KeyPair::generate();
        auto b = Ed25519KeyPair::generate();
        if (std::memcmp(a.pk.data(), b.pk.data(), 32) > 0)
            std::swap(a, b);
        return {a, b};
    }

    // Lightweight two-relay harness for loopback tests.
    // Uses real Endpoint instances but no Router/Manager — tests
    // the transport layer in isolation.
    struct QuicTestHarness
    {
        Ed25519KeyPair keys_a, keys_b;
        RouterID rid_a, rid_b;

        sr::link::Endpoint endpoint_a;
        sr::link::Endpoint endpoint_b;

        uint16_t port_a = 0;
        uint16_t port_b = 0;

        QuicTestHarness() : endpoint_a{true}, endpoint_b{true}
        {
            auto [ka, kb] = generate_sorted_keypairs();
            keys_a = ka;
            keys_b = kb;
            rid_a = RouterID{ka.pk};
            rid_b = RouterID{kb.pk};
        }

        // Start both endpoints listening on localhost with OS-assigned ports.
        // Must be called before connect_*.
        void start()
        {
            // Listen on port 0 = OS assigns a free port
            // We use the first 32 bytes of the secret key as the seed
            endpoint_a.listen(
                0,
                std::span<const std::byte, 32>{keys_a.sk.data(), 32},
                std::span<const std::byte, 32>{keys_a.pk.data(), 32});

            endpoint_b.listen(
                0,
                std::span<const std::byte, 32>{keys_b.sk.data(), 32},
                std::span<const std::byte, 32>{keys_b.pk.data(), 32});

            // TODO: read actual assigned ports from endpoint
            // For now, tests that need ports must set them after listen()
        }

        // Connect A → B
        void connect_a_to_b()
        {
            endpoint_a.connect(rid_b, "127.0.0.1", port_b);
        }

        // Connect B → A
        void connect_b_to_a()
        {
            endpoint_b.connect(rid_a, "127.0.0.1", port_a);
        }

        // Wait for connections to establish (polling)
        bool wait_established(std::chrono::milliseconds timeout = 5s)
        {
            auto deadline = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (endpoint_a.is_connected(rid_b) || endpoint_b.is_connected(rid_a))
                    return true;
                std::this_thread::sleep_for(10ms);
            }
            return false;
        }

        // Wait for BOTH directions to establish
        bool wait_both_established(std::chrono::milliseconds timeout = 5s)
        {
            auto deadline = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (endpoint_a.is_connected(rid_b) && endpoint_b.is_connected(rid_a))
                    return true;
                std::this_thread::sleep_for(10ms);
            }
            return false;
        }

        // Run event loops for a duration (allows callbacks to fire)
        void run_for(std::chrono::milliseconds duration)
        {
            std::this_thread::sleep_for(duration);
        }

        ~QuicTestHarness()
        {
            endpoint_a.close();
            endpoint_b.close();
        }
    };

}  // namespace sr::test
