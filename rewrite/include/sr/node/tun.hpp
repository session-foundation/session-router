#pragma once

#include <cstddef>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace sr::node {

// Linux TUN device for VPN tunneling.
// Reads/writes raw IP packets.

using PacketHandler = std::function<void(std::vector<std::byte>)>;

class TunDevice {
public:
    TunDevice() = default;
    ~TunDevice();

    // Create and configure the TUN device
    bool open(const std::string& name, const std::string& ip, int netmask);

    // Close the device
    void close();

    // Write an IP packet to the TUN device (inject into local network stack)
    bool write_packet(std::span<const std::byte> packet);

    // Read an IP packet from the TUN device (outbound traffic from apps)
    // Returns empty vector if no data available or error
    std::vector<std::byte> read_packet();

    // File descriptor for polling
    int fd() const { return _fd; }
    bool is_open() const { return _fd >= 0; }

    // Device name (may differ from requested if auto-assigned)
    const std::string& name() const { return _name; }

private:
    int _fd = -1;
    std::string _name;
};

}  // namespace sr::node
