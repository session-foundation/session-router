#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace sr::node {

struct Config {
    // Identity
    std::filesystem::path data_dir = "~/.session-router";
    std::filesystem::path key_file = "identity.key";

    // Network
    std::string listen_addr = "0.0.0.0";
    uint16_t listen_port = 1090;
    bool is_relay = false;

    // TUN device
    std::string tun_name = "sr0";
    std::string tun_ip = "10.0.0.1";
    int tun_netmask = 16;

    // DNS
    std::string dns_bind = "127.0.0.1:1053";
    std::string dns_upstream = "1.1.1.1";

    // Paths
    int min_path_hops = 3;
    int max_path_hops = 4;
    int target_paths = 6;
    std::chrono::seconds path_lifetime{1200};  // 20 minutes

    // Connections
    int edge_connections = 4;
    std::chrono::seconds keep_alive{10};
    std::chrono::seconds idle_timeout{60};

    // Bootstrap
    std::vector<std::string> bootstrap_files;

    // Tick
    std::chrono::milliseconds tick_interval{250};

    // Parse from INI file
    static Config from_file(const std::filesystem::path& path);

    // Parse from command line args
    static Config from_args(int argc, char** argv);
};

}  // namespace sr::node
