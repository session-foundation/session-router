#include "address/ip_range.hpp"
#include "platform.hpp"
#include "util/logging.hpp"
#include "win32/adapters.hpp"
#include "win32/exception.hpp"

#include <iphlpapi.h>

#include <vector>

namespace srouter::net
{
    static auto logcat = log::Cat("win32.net");

    class Platform_Impl : public Platform
    {
      public:
        std::optional<quic::Address> get_best_public_address(bool want_ipv4, uint16_t port) const override
        {
            std::optional<quic::Address> found;

            win32::iter_adapters([&](auto* adapter) {
                if (found)
                    return;
                for (auto* addr = adapter->FirstUnicastAddress; addr; addr = addr->Next)
                {
                    if (!addr->Address.lpSockaddr)
                        continue;
                    quic::Address a{addr->Address.lpSockaddr};
                    if (want_ipv4 ? !a.is_ipv4() : !a.is_ipv6())
                        continue;
                    if (!a.is_public_ip())
                        continue;
                    a.set_port(port);
                    found = std::move(a);
                    return;
                }
            });

            log::info(logcat, "get_best_public_address returned: {}", found);
            return found;
        }

        std::optional<ipv4_net> find_free_ipv4_net(uint8_t mask) const override
        {
            std::vector<ipv4_range> current_ranges;

            win32::iter_adapters([&](auto* adapter) {
                for (auto* addr = adapter->FirstUnicastAddress; addr; addr = addr->Next)
                {
                    if (!addr->Address.lpSockaddr)
                        continue;
                    if (addr->Address.lpSockaddr->sa_family != AF_INET)
                        continue;
                    quic::Address a{addr->Address.lpSockaddr};
                    auto prefix = static_cast<uint8_t>(addr->OnLinkPrefixLength);
                    log::debug(logcat, "Adding {}/{} to excluded search ranges", a.to_ipv4(), prefix);
                    current_ranges.emplace_back(a.to_ipv4(), prefix);
                }
            });

            return find_private_ipv4_net(std::move(current_ranges), mask);
        }

        std::string find_free_tun([[maybe_unused]] std::string_view suggest) const override
        {
            // Windows uses a fixed TUN name (cannot freely invent interface names like Linux).
            return "sr-tun0";
        }

        std::optional<int> get_interface_index(ipv4 ip) const override
        {
            std::optional<int> found;

            win32::iter_adapters([&](auto* adapter) {
                if (found)
                    return;
                for (auto* addr = adapter->FirstUnicastAddress; addr; addr = addr->Next)
                {
                    if (!addr->Address.lpSockaddr)
                        continue;
                    if (addr->Address.lpSockaddr->sa_family != AF_INET)
                        continue;
                    quic::Address a{addr->Address.lpSockaddr};
                    if (a.to_ipv4() == ip)
                    {
                        found = static_cast<int>(adapter->IfIndex);
                        return;
                    }
                }
            });

            return found;
        }

        std::optional<int> get_interface_index(ipv6 ip) const override
        {
            std::optional<int> found;

            win32::iter_adapters([&](auto* adapter) {
                if (found)
                    return;
                for (auto* addr = adapter->FirstUnicastAddress; addr; addr = addr->Next)
                {
                    if (!addr->Address.lpSockaddr)
                        continue;
                    if (addr->Address.lpSockaddr->sa_family != AF_INET6)
                        continue;
                    quic::Address a{addr->Address.lpSockaddr};
                    if (a.to_ipv6() == ip)
                    {
                        auto idx = adapter->Ipv6IfIndex ? adapter->Ipv6IfIndex : adapter->IfIndex;
                        found = static_cast<int>(idx);
                        return;
                    }
                }
            });

            return found;
        }

        std::optional<ipv4> get_interface_ipv4(std::string_view ifname) const override
        {
            std::optional<ipv4> found;

            win32::iter_adapters([&](auto* adapter) {
                if (found)
                    return;
                if (std::string{adapter->AdapterName} != ifname)
                    return;
                for (auto* addr = adapter->FirstUnicastAddress; addr; addr = addr->Next)
                {
                    if (!addr->Address.lpSockaddr)
                        continue;
                    if (addr->Address.lpSockaddr->sa_family != AF_INET)
                        continue;
                    found = quic::Address{addr->Address.lpSockaddr}.to_ipv4();
                    return;
                }
            });

            return found;
        }

        std::optional<ipv6> get_interface_ipv6(std::string_view ifname) const override
        {
            std::optional<ipv6> found;

            win32::iter_adapters([&](auto* adapter) {
                if (found)
                    return;
                if (std::string{adapter->AdapterName} != ifname)
                    return;
                for (auto* addr = adapter->FirstUnicastAddress; addr; addr = addr->Next)
                {
                    if (!addr->Address.lpSockaddr)
                        continue;
                    if (addr->Address.lpSockaddr->sa_family != AF_INET6)
                        continue;
                    found = quic::Address{addr->Address.lpSockaddr}.to_ipv6();
                    return;
                }
            });

            return found;
        }

        bool has_interface_address(ipv4 ip) const override
        {
            return get_interface_index(ip) != std::nullopt;
        }

        bool has_interface_address(ipv6 ip) const override
        {
            return get_interface_index(ip) != std::nullopt;
        }
    };

    const Platform_Impl g_plat{};

    const Platform* Platform::Default_ptr() { return &g_plat; }
}  // namespace srouter::net
