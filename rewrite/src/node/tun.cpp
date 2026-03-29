#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sr/node/tun.hpp>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>

namespace sr::node
{

    TunDevice::~TunDevice() { close(); }

    bool TunDevice::open(const std::string& name, const std::string& ip, int netmask)
    {
        _fd = ::open("/dev/net/tun", O_RDWR);
        if (_fd < 0)
            return false;

        struct ifreq ifr
        {};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if (!name.empty())
            strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);

        if (ioctl(_fd, TUNSETIFF, &ifr) < 0)
        {
            ::close(_fd);
            _fd = -1;
            return false;
        }

        _name = ifr.ifr_name;

        // Set IP address
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
        {
            ::close(_fd);
            _fd = -1;
            return false;
        }

        // Set address
        std::memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, _name.c_str(), IFNAMSIZ - 1);
        auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
        addr->sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &addr->sin_addr);
        if (ioctl(sock, SIOCSIFADDR, &ifr) < 0)
        {
            ::close(sock);
            ::close(_fd);
            _fd = -1;
            return false;
        }

        // Set netmask
        std::memset(&ifr.ifr_netmask, 0, sizeof(ifr.ifr_netmask));
        auto* mask = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
        mask->sin_family = AF_INET;
        mask->sin_addr.s_addr = htonl(~((1u << (32 - netmask)) - 1));
        if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0)
        {
            ::close(sock);
            ::close(_fd);
            _fd = -1;
            return false;
        }

        // Bring up
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0)
        {
            ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
            ioctl(sock, SIOCSIFFLAGS, &ifr);
        }

        // Set MTU
        ifr.ifr_mtu = 1500;
        ioctl(sock, SIOCSIFMTU, &ifr);

        ::close(sock);

        // Set non-blocking
        int flags = fcntl(_fd, F_GETFL, 0);
        fcntl(_fd, F_SETFL, flags | O_NONBLOCK);

        return true;
    }

    void TunDevice::close()
    {
        if (_fd >= 0)
        {
            ::close(_fd);
            _fd = -1;
        }
    }

    bool TunDevice::write_packet(std::span<const std::byte> packet)
    {
        if (_fd < 0 || packet.empty())
            return false;
        auto n = ::write(_fd, packet.data(), packet.size());
        return n == static_cast<ssize_t>(packet.size());
    }

    std::vector<std::byte> TunDevice::read_packet()
    {
        if (_fd < 0)
            return {};

        std::vector<std::byte> buf(2048);
        auto n = ::read(_fd, buf.data(), buf.size());
        if (n <= 0)
            return {};

        buf.resize(static_cast<size_t>(n));
        return buf;
    }

}  // namespace sr::node
