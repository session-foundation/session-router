#include "win32.hpp"

#include "win32/adapters.hpp"
#include "win32/windivert.hpp"
#include "win32/wintun.hpp"

#include <fmt/core.h>

namespace srouter::win32
{

    void VPNPlatform::make_route(std::string ip, std::string gw, std::string cmd)
    {
        srouter::win32::Exec(
            "route.exe", fmt::format("{} {} MASK 255.255.255.255 {} METRIC {}", cmd, ip, gw, m_Metric));
    }

    void VPNPlatform::default_route_via_interface(NetworkInterface& vpn, std::string cmd)
    {
        // route hole for loopback bacause god is dead on windows
        srouter::win32::Exec("route.exe", fmt::format("{} 127.0.0.0 MASK 255.0.0.0 0.0.0.0", cmd));
        // set up ipv4 routes
        route_via_interface(vpn, "0.0.0.0", "128.0.0.0", cmd);
        route_via_interface(vpn, "128.0.0.0", "128.0.0.0", cmd);
    }

    void VPNPlatform::route_via_interface(NetworkInterface& vpn, std::string addr, std::string mask, std::string cmd)
    {
        const auto& info = vpn.interface_info();
        if (info.addrs.empty())
            throw std::runtime_error{"win32 route_via_interface: interface has no addresses"};
        auto ifaddr = std::visit([](const auto& a) { return a.ip.to_string(); }, info.addrs[0]);
        // this changes the last 1 to a 0 so that it routes over the interface
        // this is required because windows is idiotic af
        ifaddr.back()--;
        srouter::win32::Exec("route.exe", fmt::format("{} {} MASK {} {} METRIC {}", cmd, addr, mask, ifaddr, m_Metric));
    }

    namespace
    {
        std::string ipv4_netmask_dotted(uint8_t mask)
        {
            if (mask == 0)
                return "0.0.0.0";
            uint32_t m = (mask >= 32) ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - mask));
            return fmt::format("{}.{}.{}.{}", (m >> 24) & 0xff, (m >> 16) & 0xff, (m >> 8) & 0xff, m & 0xff);
        }
    }  // namespace

    void VPNPlatform::add_route(ipv4 ip, ipv4 gateway)
    {
        make_route(ip.to_string(), gateway.to_string(), "ADD");
    }

    void VPNPlatform::add_route(ipv6 ip, ipv6 gateway)
    {
        srouter::win32::Exec(
            "route.exe",
            fmt::format("-6 ADD {}/128 {} METRIC {}", ip.to_string(), gateway.to_string(), m_Metric));
    }

    void VPNPlatform::delete_route(ipv4 ip, ipv4 gateway)
    {
        make_route(ip.to_string(), gateway.to_string(), "DELETE");
    }

    void VPNPlatform::delete_route(ipv6 ip, ipv6 gateway)
    {
        srouter::win32::Exec(
            "route.exe",
            fmt::format("-6 DELETE {}/128 {}", ip.to_string(), gateway.to_string()));
    }

    void VPNPlatform::add_route_via_interface(NetworkInterface& vpn, ipv4_range range)
    {
        route_via_interface(vpn, range.ip.to_string(), ipv4_netmask_dotted(range.mask), "ADD");
    }

    void VPNPlatform::add_route_via_interface(NetworkInterface& vpn, ipv6_range range)
    {
        const auto& info = vpn.interface_info();
        srouter::win32::Exec(
            "netsh.exe",
            fmt::format(
                "interface ipv6 add route {}/{} \"{}\"",
                range.ip.to_string(),
                range.mask,
                info.ifname));
    }

    void VPNPlatform::delete_route_via_interface(NetworkInterface& vpn, ipv4_range range)
    {
        route_via_interface(vpn, range.ip.to_string(), ipv4_netmask_dotted(range.mask), "DELETE");
    }

    void VPNPlatform::delete_route_via_interface(NetworkInterface& vpn, ipv6_range range)
    {
        const auto& info = vpn.interface_info();
        srouter::win32::Exec(
            "netsh.exe",
            fmt::format(
                "interface ipv6 delete route {}/{} \"{}\"",
                range.ip.to_string(),
                range.mask,
                info.ifname));
    }

    std::vector<quic::Address> VPNPlatform::get_non_interface_gateways(NetworkInterface& vpn)
    {
        std::set<quic::Address> gateways;

        // FIXME: This code is probably broken.  The idea here:
        // - iterate through all system interfaces
        // - if the interface has no gateway, skip it.
        // - if any of those interfaces have a network that contains our interface network(s) (that
        //   is: those in the `vpn` input), then skip it.
        // - else collect the gateway address
        //
        win32::iter_adapters([&if_info = vpn.interface_info(), &gateways](auto* a) {
            auto* igw = a->FirstGatewayAddress;
            if (!igw)
                return;
            quic::Address gw{igw->Address.lpSockaddr, igw->Address.iSockaddrLength};

            bool accept = true;
            for (auto* addr = a->FirstUnicastAddress; accept and addr; addr = addr->Next)
            {
                if (addr->Address.lpSockaddr->sa_family != AF_INET && addr->Address.lpSockaddr->sa_family != AF_INET6)
                    continue;
                quic::Address adapter_addr{addr->Address.lpSockaddr, addr->Address.iSockaddrLength};
                auto netmask_bits = addr->OnLinkPrefixLength;
                std::variant<ipv4_range, ipv6_range> adapter_range;
                if (adapter_addr.is_ipv4())
                    adapter_range = adapter_addr.to_ipv4() / netmask_bits;
                else
                    adapter_range = adapter_addr.to_ipv6() / netmask_bits;

                for (auto& a : if_info.addrs)
                {
                    auto contains = std::visit(
                        [&adapter_range]<typename Net, typename Range>(const Net& a, const Range& b) {
                            if constexpr (
                                (std::same_as<Net, ipv4_net> && std::same_as<Range, ipv4_range>)
                                || (std::same_as<Net, ipv6_net> && std::same_as<Range, ipv6_range>))
                                return b.contains(a.ip);
                            return false;
                        },
                        a,
                        adapter_range);
                    if (contains)
                    {
                        accept = false;
                        break;
                    }
                }
            }

            if (accept)
                gateways.insert(std::move(gw));
        });

        return {gateways.begin(), gateways.end()};
    }

    void VPNPlatform::add_default_route_via_interface(NetworkInterface& vpn)
    {
        // kill ipv6
        srouter::win32::Exec(
            "WindowsPowerShell\\v1.0\\powershell.exe",
            "-Command (Disable-NetAdapterBinding -Name \"* \" -ComponentID ms_tcpip6)");

        default_route_via_interface(vpn, "ADD");
    }

    void VPNPlatform::delete_default_route_via_interface(NetworkInterface& vpn)
    {
        // restore ipv6
        srouter::win32::Exec(
            "WindowsPowerShell\\v1.0\\powershell.exe",
            "-Command (Enable-NetAdapterBinding -Name \"* \" -ComponentID ms_tcpip6)");

        default_route_via_interface(vpn, "DELETE");
    }

    std::shared_ptr<NetworkInterface> VPNPlatform::obtain_interface(InterfaceInfo info, Router* router)
    {
        return wintun::make_interface(std::move(info), router);
    }

    std::shared_ptr<PacketIO> VPNPlatform::create_packet_io(
        unsigned int ifindex, const std::optional<quic::Address>& dns_upstream_src)
    {
        // we only want do this on all interfaes with windivert
        if (ifindex)
            throw std::invalid_argument{
                "cannot create packet io on explicitly specified interface, not currently "
                "supported on "
                "windows (yet)"};

        uint16_t upstream_src_port = dns_upstream_src ? dns_upstream_src->port() : 0;
        std::string udp_filter = upstream_src_port != 0
            ? fmt::format("( udp.DstPort == 53 and udp.SrcPort != {} )", upstream_src_port)
            : "udp.DstPort == 53";

        auto filter = "outbound and ( " + udp_filter + " or tcp.DstPort == 53 )";

        return WinDivert::make_interceptor(filter, [router = _ctx->router] { /* router->TriggerPump(); */ });
    }
}  // namespace srouter::win32
