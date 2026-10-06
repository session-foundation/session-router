#pragma once

#include "net/ip_headers.hpp"
#include "path/path.hpp"
#include "session.hpp"

#include <oxen/quic/utils.hpp>

#include <cstddef>

namespace srouter::session
{
    // Bytes added to each packet carried by a UDP tunnel (an embedded client's mapped UDP port):
    // the IPv6 + UDP header it is wrapped in, then the session and path layers.
    inline constexpr size_t UDP_TUNNEL_OVERHEAD = sizeof(ipv6_header) + sizeof(udp_header)
        + Session::DATA_MESSAGE_OVERHEAD + path::Path::ENCRYPT_PATH_MESSAGE_OVERHEAD;

    // A link connection's own overhead on a packet carrying one datagram: libquic's QUIC packet and
    // DATAGRAM frame overhead, plus the 2-byte datagram ID it adds because link connections enable
    // datagram splitting.
    inline constexpr size_t LINK_DATAGRAM_OVERHEAD = quic::DATAGRAM_OVERHEAD_1RTT + 2;

    // The split threshold (not a limit) for a UDP tunnel carrying QUIC at the 1200 QUIC minimum, as
    // libsession-util's tunnelled connections do: the smallest link UDP payload that carries each of
    // their packets in a single datagram.  Smaller link paths still work, but split every full-size
    // packet in two.
    inline constexpr size_t UDP_TUNNEL_UNSPLIT_LINK_PAYLOAD =
        quic::MIN_UDP_PAYLOAD + UDP_TUNNEL_OVERHEAD + LINK_DATAGRAM_OVERHEAD;

    // libquic's default probe list (DEFAULT_PMTUD_PROBES) includes this size so that link
    // connections can settle on it; if this changes, that list needs to change with it.
    static_assert(UDP_TUNNEL_UNSPLIT_LINK_PAYLOAD == 1372);

}  // namespace srouter::session
