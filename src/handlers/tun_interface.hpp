#pragma once

#include "address/address.hpp"
#include "address/ip_range.hpp"
#include "net/ip_packet.hpp"
#include "net/traffic_type.hpp"

#include <optional>
#include <string>
#include <utility>

namespace srouter::handlers
{
    // Core-side interface for the TUN endpoint.  Router holds and drives an ITunnel; the concrete
    // implementation (TunEndpoint, which needs the platform/vpn layer) lives in the full library and
    // is constructed via the full-only seam.  In embedded/core-only builds Router never constructs one
    // (the pointer stays null), so core references only this interface -- never the platform code.
    struct ITunnel
    {
        virtual ~ITunnel() = default;

        virtual void start_poller() = 0;
        virtual void stop() = 0;

        virtual std::string get_if_name() const = 0;

        virtual const ipv4_net& get_ipv4_network() const = 0;
        virtual const ipv6_net& get_ipv6_network() const = 0;

        virtual void handle_inbound_packet(IPPacket pkt, traffic_type type, NetworkAddress remote) = 0;

        virtual ipv6 map6(const NetworkAddress& remote) = 0;
        virtual std::optional<ipv4> map4(const NetworkAddress& remote) = 0;

        virtual void expire(const NetworkAddress& remote) = 0;

        virtual std::pair<std::optional<NetworkAddress>, bool> reverse_lookup(const ipv4& ip) = 0;
        virtual std::pair<std::optional<NetworkAddress>, bool> reverse_lookup(const ipv6& ip) = 0;
    };

}  // namespace srouter::handlers
