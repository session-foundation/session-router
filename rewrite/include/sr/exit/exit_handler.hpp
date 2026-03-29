#pragma once

#include <sr/contact/router_id.hpp>
#include <sr/node/tun.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace sr::exit
{

    // Exit handler manages traffic between the onion network and the public internet.
    // When this node is an exit node, IP packets arriving through paths are
    // forwarded to the internet, and responses are routed back through the path.
    //
    // Revenue model: exit nodes charge per-byte or per-session for internet access.
    //
    // Architecture:
    //   Onion path → decrypt at exit → NAT → public internet
    //   Public internet → reverse NAT → encrypt → onion path back

    // NAT mapping: tracks which internal session maps to which exit traffic
    struct NATEntry
    {
        sr::contact::RouterID client_rid;
        uint32_t internal_ip;       // client's IP inside the tunnel
        uint16_t original_src_port; // client's original source port (host byte order)
        uint32_t nat_port;          // port assigned on our external interface
        std::chrono::steady_clock::time_point last_activity;
    };

    class ExitHandler
    {
      public:
        ExitHandler() = default;

        // Enable exit mode on a TUN device
        bool enable(const std::string& exit_interface, const std::string& exit_ip, int netmask);

        // Disable exit mode
        void disable();

        // Handle a decrypted IP packet from a client that needs to exit to the internet
        void handle_exit_packet(const sr::contact::RouterID& client, std::span<const std::byte> ip_packet);

        // Handle an IP packet from the internet that needs to go back to a client
        void handle_internet_packet(std::span<const std::byte> ip_packet);

        // Set callback for sending packets back through onion paths
        using SendCallback = std::function<void(const sr::contact::RouterID& client, std::vector<std::byte> packet)>;
        void on_send_back(SendCallback cb);

        // NAT table management
        void expire_nat_entries(
            std::chrono::steady_clock::time_point now, std::chrono::seconds max_idle = std::chrono::minutes(5));
        size_t nat_table_size() const;

        bool is_enabled() const { return _enabled; }

      private:
        bool _enabled = false;
        sr::node::TunDevice _exit_tun;
        SendCallback _send_back;
        std::unordered_map<uint32_t, NATEntry> _nat_table;  // mapped_port → entry
        uint32_t _next_port = 10000;

        // Rewrite source IP/port for outgoing packets (client → internet)
        std::vector<std::byte> apply_nat(const sr::contact::RouterID& client, std::span<const std::byte> packet);

        // Reverse NAT for incoming packets (internet → client)
        std::optional<std::pair<sr::contact::RouterID, std::vector<std::byte>>> reverse_nat(
            std::span<const std::byte> packet);
    };

    // Route management for exit nodes
    class RouteManager
    {
      public:
        // Set up OS routing for exit traffic
        // This replaces the broken route_poker from upstream
        bool setup_exit_routes(const std::string& tun_name, const std::string& exit_interface);

        // Tear down routes
        void teardown_routes();

        // Enable IP forwarding (sysctl)
        static bool enable_ip_forwarding();

        // Set up iptables NAT rules
        bool setup_nat_rules(const std::string& tun_name, const std::string& exit_interface);

        // Remove iptables NAT rules
        void teardown_nat_rules();

      private:
        std::string _tun_name;
        std::string _exit_iface;
        bool _routes_active = false;
        bool _nat_active = false;
    };

}  // namespace sr::exit
