#pragma once

#include "policy.hpp"

#include <cstdint>

namespace srouter
{
    enum class traffic_type : uint8_t
    {
        UDP = 0,
        TCP = 1,
        RAW = 2,
        TUNNELED_QUIC = 3,
    };

    inline constexpr bool is_valid(traffic_type t)
    {
        return t >= traffic_type::UDP && t <= traffic_type::TUNNELED_QUIC;
    }

    inline constexpr traffic_type to_traffic_type(net::IPProtocol proto)
    {
        switch (proto)
        {
            case net::IPProtocol::UDP:
                return traffic_type::UDP;
            case net::IPProtocol::TCP:
                return traffic_type::TCP;
            default:
                return traffic_type::RAW;
        }
    }

}  // namespace srouter
