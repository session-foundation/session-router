#include <sr/node/config.hpp>

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace sr::node {

// Simple INI parser — enough for session-router config
static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    auto end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

Config Config::from_file(const std::filesystem::path& path) {
    Config cfg;
    std::ifstream file{path};
    if (!file.is_open())
        throw std::runtime_error("Cannot open config file: " + path.string());

    std::string line, section;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;

        if (line.front() == '[' && line.back() == ']') {
            section = line.substr(1, line.size() - 2);
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        auto key = trim(line.substr(0, eq));
        auto val = trim(line.substr(eq + 1));

        if (section == "router") {
            if (key == "data-dir") cfg.data_dir = val;
            else if (key == "is-relay") cfg.is_relay = (val == "true" || val == "1");
        } else if (section == "network") {
            if (key == "listen") cfg.listen_addr = val;
            else if (key == "port") cfg.listen_port = static_cast<uint16_t>(std::stoi(val));
        } else if (section == "tun") {
            if (key == "name") cfg.tun_name = val;
            else if (key == "ip") cfg.tun_ip = val;
            else if (key == "netmask") cfg.tun_netmask = std::stoi(val);
        } else if (section == "dns") {
            if (key == "bind") cfg.dns_bind = val;
            else if (key == "upstream") cfg.dns_upstream = val;
        } else if (section == "paths") {
            if (key == "hops") cfg.min_path_hops = std::stoi(val);
            else if (key == "target") cfg.target_paths = std::stoi(val);
        } else if (section == "bootstrap") {
            if (key == "file") cfg.bootstrap_files.push_back(val);
        }
    }

    return cfg;
}

Config Config::from_args([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    // TODO: CLI11 or manual arg parsing
    // For now, look for --config <path> and delegate to from_file
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string arg{argv[i]};
        if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
            return from_file(argv[i + 1]);
        }
        if (arg == "--relay") {
            cfg.is_relay = true;
        }
    }
    return cfg;
}

}  // namespace sr::node
