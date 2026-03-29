#pragma once

#include <sr/contact/router_id.hpp>
#include <sr/link/endpoint.hpp>

#include <chrono>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace sr::link
{

    // Message dispatch: routes incoming messages to registered handlers.
    // This replaces the god-object pattern — modules register what they handle.

    using MessageHandler = std::function<void(
        const sr::contact::RouterID& from,
        std::span<const std::byte> payload,
        std::function<void(std::vector<std::byte>)> respond)>;

    class Manager
    {
      public:
        explicit Manager(Endpoint& endpoint);

        // Register a handler for a BTStream method name.
        // e.g., "path_build", "gossip_rc", "session_init"
        void on(const std::string& method, MessageHandler handler);

        // Register datagram handler (data messages)
        void on_datagram(DatagramHandler handler);

        // Send helpers (delegate to endpoint)
        void send_datagram(const sr::contact::RouterID& to, std::span<const std::byte> data);

        void send_request(
            const sr::contact::RouterID& to,
            std::string_view method,
            std::span<const std::byte> payload,
            std::function<void(std::span<const std::byte>)> on_response = {});

        // Connection management
        void connect(const sr::contact::RouterID& rid, const std::string& addr, uint16_t port);
        bool is_connected(const sr::contact::RouterID& to) const;
        std::vector<sr::contact::RouterID> connected_peers() const;

      private:
        Endpoint& _endpoint;
        std::unordered_map<std::string, MessageHandler> _handlers;

        void dispatch_request(
            const sr::contact::RouterID& from,
            std::string_view method,
            std::span<const std::byte> payload,
            std::function<void(std::vector<std::byte>)> respond);
    };

}  // namespace sr::link
