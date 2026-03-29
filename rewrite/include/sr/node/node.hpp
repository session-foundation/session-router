#pragma once

#include <sr/contact/nodedb.hpp>
#include <sr/crypto/types.hpp>
#include <sr/link/endpoint.hpp>
#include <sr/link/manager.hpp>
#include <sr/node/config.hpp>
#include <sr/node/dns.hpp>
#include <sr/node/events.hpp>
#include <sr/node/tun.hpp>
#include <sr/path/onion.hpp>
#include <sr/path/path.hpp>
#include <sr/session/session.hpp>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace sr::node
{

    // Node is the thin orchestrator — wires all layers together.
    // ~200 lines, not 1,137. No god object.

    class Node
    {
      public:
        explicit Node(Config config);
        ~Node();

        // Start the node (blocks until stopped)
        void run();

        // Signal shutdown
        void stop();

        // Accessors
        const Config& config() const { return _config; }
        EventBus& events() { return _events; }
        sr::contact::NodeDB& nodedb() { return _nodedb; }

      private:
        Config _config;
        EventBus _events;

        // Identity
        sr::crypto::Ed25519KeyPair _identity;

        // Layers
        sr::contact::NodeDB _nodedb;
        sr::link::Endpoint _endpoint;
        sr::link::Manager _manager;
        TunDevice _tun;
        DnsResolver _dns;

        // Active paths and sessions
        std::vector<sr::path::Path> _paths;
        struct SessionTagHash
        {
            size_t operator()(const sr::session::SessionTag& t) const
            {
                size_t h = 0;
                for (auto b : t)
                    h = h * 31 + static_cast<size_t>(b);
                return h;
            }
        };
        std::unordered_map<sr::session::SessionTag, sr::session::Session, SessionTagHash> _sessions;

        // Runtime
        std::atomic<bool> _running{false};
        std::thread _tun_reader;

        // Tick
        void tick();
        void maintain_paths();
        void maintain_connections();
        void expire_paths();

        // Message handlers (registered with Manager)
        void handle_path_build(
            const sr::contact::RouterID& from,
            std::span<const std::byte> payload,
            std::function<void(std::vector<std::byte>)> respond);
        void handle_gossip_rc(
            const sr::contact::RouterID& from,
            std::span<const std::byte> payload,
            std::function<void(std::vector<std::byte>)> respond);
        void handle_datagram(const sr::contact::RouterID& from, std::span<const std::byte> data);

        // Path building
        void build_path();

        // TUN packet handling
        void handle_outbound_packet(std::vector<std::byte> packet);
        void handle_inbound_packet(std::span<const std::byte> packet);

        // Bootstrap
        void bootstrap();

        // Key management
        void load_or_generate_keys();
    };

}  // namespace sr::node
