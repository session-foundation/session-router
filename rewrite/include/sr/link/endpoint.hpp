#pragma once

#include <sr/contact/router_id.hpp>

#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace sr::link
{

    // Callback types for incoming data
    using DatagramHandler = std::function<void(const sr::contact::RouterID& from, std::span<const std::byte> data)>;

    using BTStreamHandler = std::function<void(
        const sr::contact::RouterID& from,
        std::string_view method,
        std::span<const std::byte> payload,
        std::function<void(std::vector<std::byte>)> respond)>;

    // Endpoint wraps oxen-libquic for session-router transport.
    // Manages QUIC connections to relay nodes.
    // Does NOT parse message contents — just delivers bytes.

    class Endpoint
    {
      public:
        explicit Endpoint(bool is_relay = false);
        ~Endpoint();

        // Start listening on a port with Ed25519 identity
        void listen(uint16_t port, std::span<const std::byte, 32> ed_seed, std::span<const std::byte, 32> ed_pubkey);

        // Connect to a relay
        void connect(const sr::contact::RouterID& rid, const std::string& addr, uint16_t port);

        // Send datagram (unreliable, for data messages)
        void send_datagram(const sr::contact::RouterID& to, std::span<const std::byte> data);

        // Send BTStream request (reliable, for control messages)
        void send_request(
            const sr::contact::RouterID& to,
            std::string_view method,
            std::span<const std::byte> payload,
            std::function<void(std::span<const std::byte>)> on_response = {});

        // Register handlers
        void on_datagram(DatagramHandler handler);
        void on_request(BTStreamHandler handler);

        // Connection management
        bool is_connected(const sr::contact::RouterID& to) const;
        size_t connection_count() const;
        std::vector<sr::contact::RouterID> connected_peers() const;

        // Close a connection
        void disconnect(const sr::contact::RouterID& rid);

        // Shut down the endpoint
        void close();

      private:
        bool _is_relay;
        DatagramHandler _dgram_handler;
        BTStreamHandler _bt_handler;

        // oxen-quic internals (opaque — implementation depends on quic library)
        struct Impl;
        std::unique_ptr<Impl> _impl;
    };

}  // namespace sr::link
