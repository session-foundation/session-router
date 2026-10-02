#pragma once

#include "platform.hpp"
#include "router/router.hpp"
#include "win32/exec.hpp"

#include <winsock2.h>

#include <windows.h>

#include <iphlpapi.h>
#include <session/router_context.hpp>

namespace srouter::win32
{
    using namespace srouter::vpn;
    class VPNPlatform : public Platform, public AbstractRouteManager
    {
        srouter::Context* const _ctx;
        const int m_Metric{2};

        const auto& Net() const { return _ctx->router->net(); }

        void make_route(std::string ip, std::string gw, std::string cmd);

        void default_route_via_interface(NetworkInterface& vpn, std::string cmd);

        void route_via_interface(NetworkInterface& vpn, std::string addr, std::string mask, std::string cmd);

      public:
        VPNPlatform(const VPNPlatform&) = delete;
        VPNPlatform(VPNPlatform&&) = delete;

        VPNPlatform(srouter::Context* ctx) : Platform{}, _ctx{ctx} {}

        ~VPNPlatform() override = default;

        // Upstream AbstractRouteManager split Address/IPRange into ipv4/ipv6 overloads;
        // win32.hpp was still on the old quic::Address / IPRange signatures.
        void add_route(ipv4 ip, ipv4 gateway) override;
        void add_route(ipv6 ip, ipv6 gateway) override;

        void delete_route(ipv4 ip, ipv4 gateway) override;
        void delete_route(ipv6 ip, ipv6 gateway) override;

        void add_route_via_interface(NetworkInterface& vpn, ipv4_range range) override;
        void add_route_via_interface(NetworkInterface& vpn, ipv6_range range) override;

        void delete_route_via_interface(NetworkInterface& vpn, ipv4_range range) override;
        void delete_route_via_interface(NetworkInterface& vpn, ipv6_range range) override;

        std::vector<quic::Address> get_non_interface_gateways(NetworkInterface& vpn) override;

        void add_default_route_via_interface(NetworkInterface& vpn) override;

        void delete_default_route_via_interface(NetworkInterface& vpn) override;

        std::shared_ptr<NetworkInterface> obtain_interface(InterfaceInfo info, Router* router) override;

        std::shared_ptr<PacketIO> create_packet_io(
            unsigned int ifindex, const std::optional<quic::Address>& dns_upstream_src) override;

        AbstractRouteManager& RouteManager() override { return *this; }
    };

}  // namespace srouter::win32
