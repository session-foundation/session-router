#include <poll.h>
#include <sodium.h>
#include <sr/crypto/dh.hpp>
#include <sr/node/node.hpp>
#include <sr/path/onion.hpp>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

namespace sr::node
{

    using namespace sr::crypto;
    using namespace sr::contact;
    using namespace sr::path;

    Node::Node(Config config) : _config{std::move(config)}, _endpoint{_config.is_relay}, _manager{_endpoint}
    {
        sodium_init_once();
        load_or_generate_keys();

        // Register message handlers with the dispatch layer
        _manager.on("path_build", [this](auto& from, auto payload, auto respond) {
            handle_path_build(from, payload, std::move(respond));
        });
        _manager.on("gossip_rc", [this](auto& from, auto payload, auto respond) {
            handle_gossip_rc(from, payload, std::move(respond));
        });
        _manager.on_datagram([this](auto& from, auto data) { handle_datagram(from, data); });

        // Wire up events
        _events.on(Event::PATH_BUILT, [](Event, const EventData&) {
            // TODO: try pending sessions on new path
        });
        _events.on(Event::PATH_DIED, [](Event, const EventData&) {
            // TODO: rebuild path, notify affected sessions
        });
    }

    Node::~Node() { stop(); }

    void Node::run()
    {
        _running = true;

        // Start listening
        auto seed = std::span<const std::byte, 32>{reinterpret_cast<const std::byte*>(_identity.sk.data()), 32};
        auto pk = std::span<const std::byte, 32>{reinterpret_cast<const std::byte*>(_identity.pk.data()), 32};
        _endpoint.listen(_config.listen_port, seed, pk);

        // Open TUN device
        if (!_tun.open(_config.tun_name, _config.tun_ip, _config.tun_netmask))
        {
            std::cerr << "Failed to open TUN device " << _config.tun_name << "\n";
            std::cerr << "Try running with CAP_NET_ADMIN or as root\n";
            // Continue without TUN — useful for relay-only mode
        }

        // Start DNS
        auto colon = _config.dns_bind.find(':');
        if (colon != std::string::npos)
        {
            auto dns_addr = _config.dns_bind.substr(0, colon);
            auto dns_port = static_cast<uint16_t>(std::stoi(_config.dns_bind.substr(colon + 1)));
            _dns.start(dns_addr, dns_port, _config.dns_upstream);
        }

        // Bootstrap
        bootstrap();

        // Start TUN reader thread
        if (_tun.is_open())
        {
            _tun_reader = std::thread([this] {
                struct pollfd pfd
                {};
                pfd.fd = _tun.fd();
                pfd.events = POLLIN;

                while (_running)
                {
                    if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN))
                    {
                        auto pkt = _tun.read_packet();
                        if (!pkt.empty())
                            handle_outbound_packet(std::move(pkt));
                    }
                }
            });
        }

        std::cout << "Session Router running" << " [" << (_config.is_relay ? "relay" : "client") << "]"
                  << " port=" << _config.listen_port << " tun=" << (_tun.is_open() ? _config.tun_name : "none") << "\n";

        // Main tick loop
        while (_running)
        {
            tick();
            std::this_thread::sleep_for(_config.tick_interval);
        }
    }

    void Node::stop()
    {
        _running = false;
        if (_tun_reader.joinable())
            _tun_reader.join();
        _tun.close();
        _dns.stop();
        _endpoint.close();
    }

    void Node::tick()
    {
        expire_paths();
        maintain_paths();
        if (_config.is_relay)
            maintain_connections();
    }

    void Node::expire_paths()
    {
        auto now = std::chrono::steady_clock::now();
        auto it = _paths.begin();
        while (it != _paths.end())
        {
            if (it->is_expired(now))
            {
                _events.emit(Event::PATH_EXPIRED);
                it = _paths.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    void Node::maintain_paths()
    {
        // Build new paths if below target
        while (static_cast<int>(_paths.size()) < _config.target_paths && _nodedb.has_min_rcs(6))
        {
            build_path();
        }
    }

    void Node::maintain_connections()
    {
        // Relay mode: try to connect to more relays for mesh
        // TODO: full mesh maintenance logic
    }

    void Node::build_path()
    {
        // Select random relays for hops
        auto rcs = _nodedb.random_rcs(static_cast<size_t>(_config.min_path_hops));
        if (rcs.empty())
            return;

        // Generate ephemeral keys for path building
        auto ephemeral = Ed25519KeyPair::generate();

        auto result = build_onion(rcs, ephemeral, _config.path_lifetime);

        // Send path build to first hop
        std::vector<std::byte> build_msg(result.frames.begin(), result.frames.end());
        _manager.send_request(
            rcs[0].router_id(),
            "path_build",
            build_msg,
            [this, hops = std::move(result.hops)](std::span<const std::byte>) {
                // Path build succeeded
                Path path{hops};
                path.set_established();
                _paths.push_back(std::move(path));
                _events.emit(Event::PATH_BUILT);
            });
    }

    void Node::handle_path_build(
        [[maybe_unused]] const RouterID& from,
        [[maybe_unused]] std::span<const std::byte> payload,
        [[maybe_unused]] std::function<void(std::vector<std::byte>)> respond)
    {
        // Relay: decrypt our frame, store transit hop, forward to next
        if (!_config.is_relay)
            return;

        if (payload.size() < BUILD_MSG_SIZE)
            return;

        // Decrypt our frame (first frame)
        auto frame = payload.subspan(0, BUILD_FRAME_SIZE);
        auto df = decrypt_build_frame(frame, _identity.sk, _identity.pk);
        if (!df)
            return;

        // TODO: store transit hop, forward remaining frames to df->upstream
        // For now, acknowledge
        respond({});
    }

    void Node::handle_gossip_rc(
        [[maybe_unused]] const RouterID& from,
        std::span<const std::byte> payload,
        [[maybe_unused]] std::function<void(std::vector<std::byte>)> respond)
    {
        // Parse and store the relay contact
        auto rc = RelayContact::from_bt(payload);
        if (rc && rc->verify())
        {
            _nodedb.put_rc(*rc);
            _events.emit(Event::RC_UPDATED, rc->router_id());
        }
    }

    void Node::handle_datagram([[maybe_unused]] const RouterID& from, [[maybe_unused]] std::span<const std::byte> data)
    {
        // TODO: peel onion layer (if transit) or decrypt session data (if terminal)
        // and deliver to TUN device
    }

    void Node::handle_outbound_packet(std::vector<std::byte> packet)
    {
        // TODO: look up destination, find session, encrypt, send through path
        // For now, drop
        (void)packet;
    }

    void Node::handle_inbound_packet(std::span<const std::byte> packet) { _tun.write_packet(packet); }

    void Node::bootstrap()
    {
        // TODO: load bootstrap RCs from files, connect, fetch initial routing table
        // For now, just log
        if (_nodedb.size() < 6)
        {
            std::cout << "NodeDB has " << _nodedb.size() << " RCs (need 6 minimum). Bootstrap required.\n";
        }
    }

    void Node::load_or_generate_keys()
    {
        auto key_path = _config.data_dir / _config.key_file;

        if (std::filesystem::exists(key_path))
        {
            // Load existing keys
            std::ifstream f{key_path, std::ios::binary};
            if (f.read(reinterpret_cast<char*>(_identity.sk.data()), 64))
            {
                // Derive pubkey from secret key
                crypto_sign_ed25519_sk_to_pk(
                    reinterpret_cast<unsigned char*>(_identity.pk.data()),
                    reinterpret_cast<const unsigned char*>(_identity.sk.data()));
                return;
            }
        }

        // Generate new keys
        _identity = Ed25519KeyPair::generate();

        // Save with restricted permissions (secret key must not be world-readable)
        std::filesystem::create_directories(_config.data_dir);
        std::ofstream f{key_path, std::ios::binary};
        f.write(reinterpret_cast<const char*>(_identity.sk.data()), 64);
        f.close();
        std::filesystem::permissions(
            key_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    }

}  // namespace sr::node
