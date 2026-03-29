#include <arpa/inet.h>
#include <sr/exit/exit_handler.hpp>

#include <cstring>
#include <fstream>

namespace sr::exit
{

    bool ExitHandler::enable(const std::string& exit_interface, const std::string& exit_ip, int netmask)
    {
        if (!_exit_tun.open(exit_interface, exit_ip, netmask))
            return false;
        _enabled = true;
        return true;
    }

    void ExitHandler::disable()
    {
        _enabled = false;
        _exit_tun.close();
        _nat_table.clear();
    }

    void ExitHandler::handle_exit_packet(const sr::contact::RouterID& client, std::span<const std::byte> ip_packet)
    {
        if (!_enabled)
            return;

        auto natted = apply_nat(client, ip_packet);
        if (!natted.empty())
            _exit_tun.write_packet(natted);
    }

    void ExitHandler::handle_internet_packet(std::span<const std::byte> ip_packet)
    {
        if (!_enabled || !_send_back)
            return;

        auto result = reverse_nat(ip_packet);
        if (result)
            _send_back(result->first, std::move(result->second));
    }

    void ExitHandler::on_send_back(SendCallback cb) { _send_back = std::move(cb); }

    void ExitHandler::expire_nat_entries(std::chrono::steady_clock::time_point now, std::chrono::seconds max_idle)
    {
        for (auto it = _nat_table.begin(); it != _nat_table.end();)
        {
            if ((now - it->second.last_activity) > max_idle)
                it = _nat_table.erase(it);
            else
                ++it;
        }
    }

    size_t ExitHandler::nat_table_size() const { return _nat_table.size(); }

    std::vector<std::byte> ExitHandler::apply_nat(
        const sr::contact::RouterID& client, std::span<const std::byte> packet)
    {
        // Minimal IPv4 header check
        if (packet.size() < 20)
            return {};

        // Get source port from transport header (TCP/UDP both have port at offset 0)
        uint8_t ihl = (static_cast<uint8_t>(packet[0]) & 0x0F) * 4;
        if (packet.size() < static_cast<size_t>(ihl) + 4)
            return {};

        uint16_t src_port;
        std::memcpy(&src_port, packet.data() + ihl, 2);

        // Find or create NAT entry
        uint32_t key = _next_port;
        bool found = false;
        for (auto& [port, entry] : _nat_table)
        {
            if (entry.client_rid == client && entry.mapped_port == ntohs(src_port))
            {
                key = port;
                entry.last_activity = std::chrono::steady_clock::now();
                found = true;
                break;
            }
        }

        if (!found)
        {
            NATEntry entry;
            entry.client_rid = client;
            entry.mapped_port = _next_port;
            entry.last_activity = std::chrono::steady_clock::now();
            std::memcpy(&entry.internal_ip, packet.data() + 12, 4);
            _nat_table[_next_port] = entry;
            key = _next_port++;
            if (_next_port > 65534)
                _next_port = 10000;
        }

        // Rewrite packet (copy + modify source port)
        std::vector<std::byte> out(packet.begin(), packet.end());
        uint16_t new_port = htons(static_cast<uint16_t>(key));
        std::memcpy(out.data() + ihl, &new_port, 2);

        return out;
    }

    std::optional<std::pair<sr::contact::RouterID, std::vector<std::byte>>> ExitHandler::reverse_nat(
        std::span<const std::byte> packet)
    {
        if (packet.size() < 20)
            return std::nullopt;

        uint8_t ihl = (static_cast<uint8_t>(packet[0]) & 0x0F) * 4;
        if (packet.size() < static_cast<size_t>(ihl) + 4)
            return std::nullopt;

        // Destination port is at offset ihl+2
        uint16_t dst_port;
        std::memcpy(&dst_port, packet.data() + ihl + 2, 2);
        uint32_t port_key = ntohs(dst_port);

        auto it = _nat_table.find(port_key);
        if (it == _nat_table.end())
            return std::nullopt;

        it->second.last_activity = std::chrono::steady_clock::now();

        // Restore original destination port and IP
        std::vector<std::byte> out(packet.begin(), packet.end());
        uint16_t orig_port = htons(static_cast<uint16_t>(it->second.mapped_port));
        std::memcpy(out.data() + ihl + 2, &orig_port, 2);
        std::memcpy(out.data() + 16, &it->second.internal_ip, 4);

        return std::make_pair(it->second.client_rid, std::move(out));
    }

    // RouteManager implementation
    bool RouteManager::enable_ip_forwarding()
    {
        std::ofstream f{"/proc/sys/net/ipv4/ip_forward"};
        if (!f.is_open())
            return false;
        f << "1";
        return f.good();
    }

    bool RouteManager::setup_exit_routes(const std::string& tun_name, const std::string& exit_interface)
    {
        _tun_name = tun_name;
        _exit_iface = exit_interface;

        if (!enable_ip_forwarding())
            return false;

        // Add default route through our TUN for exit traffic
        // ip route add default dev <tun> table 100
        // ip rule add from <tun_subnet> lookup 100
        std::string cmd = "ip route add default dev " + tun_name + " table 100";
        if (system(cmd.c_str()) != 0)
            return false;

        _routes_active = true;
        return true;
    }

    void RouteManager::teardown_routes()
    {
        if (!_routes_active)
            return;

        std::string cmd = "ip route del default dev " + _tun_name + " table 100";
        system(cmd.c_str());
        _routes_active = false;
    }

    bool RouteManager::setup_nat_rules(const std::string& tun_name, const std::string& exit_interface)
    {
        // iptables -t nat -A POSTROUTING -o <exit_iface> -j MASQUERADE
        // iptables -A FORWARD -i <tun> -o <exit_iface> -j ACCEPT
        // iptables -A FORWARD -i <exit_iface> -o <tun> -m state --state RELATED,ESTABLISHED -j ACCEPT

        std::string cmd1 = "iptables -t nat -A POSTROUTING -o " + exit_interface + " -j MASQUERADE";
        std::string cmd2 = "iptables -A FORWARD -i " + tun_name + " -o " + exit_interface + " -j ACCEPT";
        std::string cmd3 = "iptables -A FORWARD -i " + exit_interface + " -o " + tun_name
            + " -m state --state RELATED,ESTABLISHED -j ACCEPT";

        if (system(cmd1.c_str()) != 0)
            return false;
        if (system(cmd2.c_str()) != 0)
            return false;
        if (system(cmd3.c_str()) != 0)
            return false;

        _nat_active = true;
        return true;
    }

    void RouteManager::teardown_nat_rules()
    {
        if (!_nat_active)
            return;

        std::string cmd1 = "iptables -t nat -D POSTROUTING -o " + _exit_iface + " -j MASQUERADE";
        std::string cmd2 = "iptables -D FORWARD -i " + _tun_name + " -o " + _exit_iface + " -j ACCEPT";
        std::string cmd3 = "iptables -D FORWARD -i " + _exit_iface + " -o " + _tun_name
            + " -m state --state RELATED,ESTABLISHED -j ACCEPT";

        system(cmd1.c_str());
        system(cmd2.c_str());
        system(cmd3.c_str());
        _nat_active = false;
    }

}  // namespace sr::exit
