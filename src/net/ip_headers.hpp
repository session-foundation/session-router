#pragma once

#if defined(__MINGW32__)
#include <in6addr.h>
#elif defined(_WIN32)
// MSVC's in6addr.h is not self-contained.
#include <ws2tcpip.h>
#else
#include <netinet/ip6.h>
#endif
#include <oxenc/endian.h>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

namespace srouter
{
    struct ip_header
    {
        uint8_t version_ihl;  // high nibble: IP version; low nibble: header length in 32-bit words
        uint8_t service_type;
        uint16_t total_len;  // entire packet size
        uint16_t id;
        uint16_t frag_off;  // fragmentation offset
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t src;
        uint32_t dest;

        constexpr uint8_t version() const { return version_ihl >> 4; }

        /// Header length in bytes, including any options.
        constexpr size_t header_size() const { return (version_ihl & 0x0f) * size_t{4}; }
    };

    static_assert(sizeof(ip_header) == 20);
    static_assert([] {
        ip_header h{};
        h.version_ihl = 0x45;
        return h.version() == 4 && h.header_size() == 20;
    }());

    struct ipv6_header
    {
        uint32_t ver_tc_flow;  // big-endian: 4 bits version, 8 bits traffic class, 20 bits flow label
        uint16_t payload_len;
        uint8_t protocol;
        uint8_t hoplimit;
        in6_addr src;
        in6_addr dest;

        constexpr uint8_t version() const { return static_cast<uint8_t>(get(28, 0xf)); }
        constexpr void version(uint8_t v) { set(28, 0xf, v); }

        constexpr uint8_t tclass() const { return static_cast<uint8_t>(get(20, 0xff)); }
        constexpr void tclass(uint8_t tc) { set(20, 0xff, tc); }

        /// The flow label, in host order.
        constexpr uint32_t flowlabel() const { return get(0, 0xfffff); }
        constexpr void flowlabel(uint32_t label) { set(0, 0xfffff, label); }

      private:
        constexpr uint32_t get(int shift, uint32_t mask) const
        {
            return (oxenc::big_to_host(ver_tc_flow) >> shift) & mask;
        }

        constexpr void set(int shift, uint32_t mask, uint32_t val)
        {
            ver_tc_flow =
                oxenc::host_to_big((oxenc::big_to_host(ver_tc_flow) & ~(mask << shift)) | ((val & mask) << shift));
        }
    };

    static_assert(sizeof(ipv6_header) == 40);
    static_assert([] {
        ipv6_header h{};
        auto fields_are = [&h](uint8_t v, uint8_t tc, uint32_t fl) {
            return h.version() == v && h.tclass() == tc && h.flowlabel() == fl;
        };
        h.version(6);
        h.tclass(0xab);
        h.flowlabel(0xcdef1);
        bool ok = fields_are(6, 0xab, 0xcdef1)
            && std::bit_cast<std::array<uint8_t, 4>>(h.ver_tc_flow) == std::array<uint8_t, 4>{0x6a, 0xbc, 0xde, 0xf1};
        h.version(9);
        ok = ok && fields_are(9, 0xab, 0xcdef1);
        h.tclass(0x12);
        ok = ok && fields_are(9, 0x12, 0xcdef1);
        h.flowlabel(0x34567);
        return ok && fields_are(9, 0x12, 0x34567);
    }());

    enum class TCPFLAG : uint8_t
    {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PUSH = 0x08,
        ACK = 0x10,
        URG = 0x20
    };

    struct tcp_header
    {
        uint16_t src;           // src addr or port
        uint16_t dest;          // dst addr or port
        uint32_t seqno;         // sequence number
        uint32_t ack;           // ack number
        uint8_t data_off_rsvd;  // high nibble: data offset in 32-bit words; low nibble: reserved
        uint8_t flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urg_ptr;  // urgent ptr
    };
    static_assert(sizeof(tcp_header) == 20);

    struct udp_header
    {
        uint16_t src;
        uint16_t dest;
        uint16_t len;  // datagram length
        uint16_t checksum;
    };
    static_assert(sizeof(udp_header) == 8);

}  // namespace srouter
