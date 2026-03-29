#include <arpa/inet.h>
#include <sr/exit/exit_handler.hpp>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sys/wait.h>
#include <unistd.h>

namespace sr::exit
{

    // Recalculate IPv4 header checksum (RFC 1071)
    static void recalc_ip_checksum(std::span<std::byte> packet)
    {
        if (packet.size() < 20)
            return;
        uint8_t ihl = (static_cast<uint8_t>(packet[0]) & 0x0F) * 4;
        if (packet.size() < ihl)
            return;

        // Zero the checksum field before calculating
        packet[10] = std::byte{0};
        packet[11] = std::byte{0};

        uint32_t sum = 0;
        for (size_t i = 0; i < ihl; i += 2)
        {
            uint16_t word;
            std::memcpy(&word, packet.data() + i, 2);
            sum += ntohs(word);
        }
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

        uint16_t checksum = htons(static_cast<uint16_t>(~sum));
        std::memcpy(packet.data() + 10, &checksum, 2);
    }

    // Update TCP/UDP checksum incrementally after port change (RFC 1624)
    static void update_transport_checksum(
        std::span<std::byte> packet, size_t cksum_offset, uint16_t old_port, uint16_t new_port)
    {
        if (packet.size() < cksum_offset + 2)
            return;

        uint16_t old_cksum;
        std::memcpy(&old_cksum, packet.data() + cksum_offset, 2);
        if (old_cksum == 0)
            return;  // UDP with no checksum

        uint32_t sum = static_cast<uint16_t>(~ntohs(old_cksum));
        sum += static_cast<uint16_t>(~ntohs(old_port));
        sum += ntohs(new_port);
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

        uint16_t new_cksum = htons(static_cast<uint16_t>(~sum));
        if (new_cksum == 0)
            new_cksum = 0xFFFF;  // UDP: 0 means no checksum
        std::memcpy(packet.data() + cksum_offset, &new_cksum, 2);
    }

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

        // Rewrite packet (copy + modify source port + fix checksums)
        std::vector<std::byte> out(packet.begin(), packet.end());
        uint16_t old_port_ne;
        std::memcpy(&old_port_ne, out.data() + ihl, 2);
        uint16_t new_port = htons(static_cast<uint16_t>(key));
        std::memcpy(out.data() + ihl, &new_port, 2);

        // Update transport checksum (TCP: offset ihl+16, UDP: offset ihl+6)
        uint8_t protocol = static_cast<uint8_t>(out[9]);
        if (protocol == 6 && out.size() >= static_cast<size_t>(ihl) + 18)  // TCP
            update_transport_checksum(out, ihl + 16, old_port_ne, new_port);
        else if (protocol == 17 && out.size() >= static_cast<size_t>(ihl) + 8)  // UDP
            update_transport_checksum(out, ihl + 6, old_port_ne, new_port);

        // Recalculate IP header checksum
        recalc_ip_checksum(out);

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

        // Restore original destination port and IP, fix checksums
        std::vector<std::byte> out(packet.begin(), packet.end());
        uint16_t old_port_ne;
        std::memcpy(&old_port_ne, out.data() + ihl + 2, 2);
        uint16_t orig_port = htons(static_cast<uint16_t>(it->second.mapped_port));
        std::memcpy(out.data() + ihl + 2, &orig_port, 2);
        std::memcpy(out.data() + 16, &it->second.internal_ip, 4);

        // Update transport checksum
        uint8_t protocol = static_cast<uint8_t>(out[9]);
        if (protocol == 6 && out.size() >= static_cast<size_t>(ihl) + 18)
            update_transport_checksum(out, ihl + 16, old_port_ne, orig_port);
        else if (protocol == 17 && out.size() >= static_cast<size_t>(ihl) + 8)
            update_transport_checksum(out, ihl + 6, old_port_ne, orig_port);

        recalc_ip_checksum(out);

        return std::make_pair(it->second.client_rid, std::move(out));
    }

    // RouteManager implementation

    // Validate interface name: alphanumeric, dash, underscore only. Max IFNAMSIZ.
    static bool is_safe_iface_name(const std::string& s)
    {
        if (s.empty() || s.size() > 15)
            return false;
        return std::all_of(s.begin(), s.end(), [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_';
        });
    }

    // Execute a command safely via fork/execvp (no shell, no injection)
    static int safe_exec(const std::vector<std::string>& args)
    {
        std::vector<const char*> argv;
        for (const auto& a : args)
            argv.push_back(a.c_str());
        argv.push_back(nullptr);

        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0)
        {
            execvp(argv[0], const_cast<char* const*>(argv.data()));
            _exit(127);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

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
        if (!is_safe_iface_name(tun_name) || !is_safe_iface_name(exit_interface))
            return false;

        _tun_name = tun_name;
        _exit_iface = exit_interface;

        if (!enable_ip_forwarding())
            return false;

        if (safe_exec({"ip", "route", "add", "default", "dev", tun_name, "table", "100"}) != 0)
            return false;

        _routes_active = true;
        return true;
    }

    void RouteManager::teardown_routes()
    {
        if (!_routes_active)
            return;
        safe_exec({"ip", "route", "del", "default", "dev", _tun_name, "table", "100"});
        _routes_active = false;
    }

    bool RouteManager::setup_nat_rules(const std::string& tun_name, const std::string& exit_interface)
    {
        if (!is_safe_iface_name(tun_name) || !is_safe_iface_name(exit_interface))
            return false;

        if (safe_exec({"iptables", "-t", "nat", "-A", "POSTROUTING", "-o", exit_interface, "-j", "MASQUERADE"}) != 0)
            return false;
        if (safe_exec({"iptables", "-A", "FORWARD", "-i", tun_name, "-o", exit_interface, "-j", "ACCEPT"}) != 0)
            return false;
        if (safe_exec({"iptables", "-A", "FORWARD", "-i", exit_interface, "-o", tun_name,
                        "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}) != 0)
            return false;

        _nat_active = true;
        return true;
    }

    void RouteManager::teardown_nat_rules()
    {
        if (!_nat_active)
            return;
        safe_exec({"iptables", "-t", "nat", "-D", "POSTROUTING", "-o", _exit_iface, "-j", "MASQUERADE"});
        safe_exec({"iptables", "-D", "FORWARD", "-i", _tun_name, "-o", _exit_iface, "-j", "ACCEPT"});
        safe_exec({"iptables", "-D", "FORWARD", "-i", _exit_iface, "-o", _tun_name,
                    "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"});
        _nat_active = false;
    }

}  // namespace sr::exit
