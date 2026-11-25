#include "ip_packet.hpp"

#include "net/policy.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"
#include "util/time.hpp"

#include <oxenc/endian.h>

#include <cstddef>
#include <utility>

namespace srouter
{
    static auto logcat = log::Cat("ip_packet");

    namespace
    {
        constexpr size_t TCP_CSUM_OFF = offsetof(struct tcp_header, checksum);
        constexpr size_t UDP_CSUM_OFF = offsetof(struct udp_header, checksum);
        constexpr size_t ICMP_CSUM_OFF = 2;
        constexpr size_t ICMPv4_HEADER_SIZE = 8;
        constexpr size_t ICMPv6_HEADER_SIZE = 4;

        constexpr uint32_t add32_cs(uint32_t x) { return uint32_t{x & 0xFFff} + uint32_t{x >> 16}; }
        constexpr uint32_t add32_cs(const ipv4& x) { return add32_cs(oxenc::host_to_big(x.addr)); }

        constexpr uint32_t sub32_cs(uint32_t x) { return add32_cs(~x); }
        constexpr uint32_t sub32_cs(const ipv4& x) { return sub32_cs(oxenc::host_to_big(x.addr)); }

        constexpr uint32_t add32x4_cs(std::span<const uint32_t, 4> x)
        {
            return add32_cs(x[0]) + add32_cs(x[1]) + add32_cs(x[2]) + add32_cs(x[3]);
        }
        constexpr uint32_t sub32x4_cs(std::span<const uint32_t, 4> x)
        {
            return sub32_cs(x[0]) + sub32_cs(x[1]) + sub32_cs(x[2]) + sub32_cs(x[3]);
        }

        uint16_t ip_checksum(const uint8_t* buf, size_t sz)
        {
            uint32_t sum = 0;

            while (sz > 1)
            {
                sum += *(uint16_t*)(buf);
                sz -= sizeof(uint16_t);
                buf += sizeof(uint16_t);
            }

            if (sz != 0)
            {
                uint16_t x = 0;
                *(uint8_t*)&x = *buf;
                sum += x;
            }

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return uint16_t((~sum) & 0xFFff);
        }

        uint16_t update_ipv4_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4& new_src, const ipv4& new_dest)
        {
            uint32_t sum = old_sum + add32_cs(old_src) + add32_cs(old_dest) + sub32_cs(new_src) + sub32_cs(new_dest);

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return uint16_t(sum & 0xFFff);
        }

        uint16_t update_ipv4_tcp_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4& new_src, const ipv4& new_dest)
        {
            auto new_sum = update_ipv4_checksum(old_sum, old_src, old_dest, new_src, new_dest);
            // With 1's complement, 0xffff is -0 but that can never actually appear in a checksum
            // with any non-zero bytes (which will always be present here), so this corrects it to
            // the proper 0x000 (+0) value that it should have:
            return new_sum == 0xFFff ? 0x0000 : new_sum;
        }

        uint16_t update_ipv4_udp_checksum(
            uint16_t old_sum, uint32_t old_src, uint32_t old_dest, const ipv4& new_src, const ipv4& new_dest)
        {
            if (old_sum == 0x0000)
                return old_sum;  // 0 is used to indicate "no checksum", don't change

            return update_ipv4_checksum(old_sum, old_src, old_dest, new_src, new_dest);
        }

        uint16_t update_ipv6_checksum(
            uint16_t old_sum,
            std::span<const uint32_t, 4> old_src,
            std::span<const uint32_t, 4> old_dest,
            std::span<const uint32_t, 4> new_src,
            std::span<const uint32_t, 4> new_dest)
        {
            // It seems a little counterintuitive that we aren't doing endian conversions here, but
            // that's actually okay because even if we have a "wrong" byte order interpretation, we
            // have the same wrong interpretation for old_sum, and because we're using 1's
            // complement, it all works out in the end regardless of endianness.
            uint32_t sum = uint32_t{old_sum} + add32x4_cs(old_src) + add32x4_cs(old_dest) + sub32x4_cs(new_src)
                + sub32x4_cs(new_dest);

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return static_cast<uint16_t>(sum & 0xFFff);
        }

        // Modifies the payload's checksum at `checksumoff` to account for a change in source and
        // destination IPv6 addresses.  Unlike IPv4 which has a checksum over source and dest, IPv6
        // does not, and some protocols require it under IPv6 (such as UDP where it can be optional
        // under IPv4, and ICMP(v4) which doesn't checksum addresses at all, unlike ICMPv6).
        void update_ipv6_proto_checksum(
            std::span<std::byte> payload,
            size_t fragoff,
            size_t chksumoff,
            std::span<const uint32_t, 4> old_src,
            std::span<const uint32_t, 4> old_dest,
            std::span<const uint32_t, 4> new_src,
            std::span<const uint32_t, 4> new_dest)
        {
            if (fragoff > chksumoff || payload.size() < chksumoff - fragoff + 2)
                return;

            auto& check = *reinterpret_cast<uint16_t*>(payload.data() + chksumoff - fragoff);

            // Unlike UDP in IPv4, in IPv6 the UDP checksum is always required, thus we don't
            // special-case it being set to 0x0000 here as we do for IPv4 UDP.

            check = update_ipv6_checksum(check, old_src, old_dest, new_src, new_dest);

            // With 1's complement, 0xffff is -0 but that can never actually appear in a checksum
            // with any non-zero bytes (which will always be present here), so this corrects it to
            // the proper 0x000 (+0) value that it should have:
            if (check == 0xFFff)
                check = 0x0000;
        }

        // IPv6 checksum calculator using a pseudo-header of fields from the given ipv6 header.
        // This is used for the checksum calculation of TCP/UDP/ICMP within an IPv6 packet as the
        // IPv6 header itself does not have a checksum (unlike IPv4).
        //
        // The return 2-byte value should be written as-is (i.e. no endian conversion performed).
        uint16_t ipv6_proto_checksum(const ipv6_header& hdr, std::span<const std::byte> payload)
        {
            uint32_t sum = 0;
            // Checksum starts with a pseudo-header calculation over 40 bytes:
            // [src(16B)] [dest(16B)] [payloadlen(4B)] [0(3B)] [protocol(1B)]
            sum += add32x4_cs(std::span<const uint32_t, 4>{reinterpret_cast<const uint32_t*>(hdr.src.s6_addr), 4});
            sum += add32x4_cs(std::span<const uint32_t, 4>{reinterpret_cast<const uint32_t*>(hdr.dest.s6_addr), 4});
            sum += hdr.payload_len;
            sum += oxenc::little_endian ? static_cast<uint16_t>(hdr.protocol) << 8 : hdr.protocol;
            if (payload.size() % 2 == 1)
            {
                // If payload is odd then pretend there is an extra 0 after the last byte:
                if (oxenc::little_endian)
                    sum += static_cast<uint16_t>(payload.back());
                else
                    sum += static_cast<uint16_t>(payload.back()) << 8;
                payload = payload.subspan(0, payload.size() - 1);
            }
            for (auto x :
                 std::span<const uint16_t>{reinterpret_cast<const uint16_t*>(payload.data()), payload.size() / 2})
                sum += x;

            sum = (sum & 0xFFff) + (sum >> 16);
            sum += sum >> 16;

            return ~static_cast<uint16_t>(sum);
        }

    }  // namespace

    IPPacket::IPPacket(size_t sz)
    {
        if (sz and sz < MIN_PACKET_SIZE)
            throw std::invalid_argument{"Buffer size is too small for an IP packet!"};
        _buf.resize(sz, std::byte{0});
    }

    IPPacket::IPPacket(std::vector<std::byte>&& data) : _buf{std::move(data)}
    {
        if (_buf.size() < MIN_PACKET_SIZE)
            throw std::invalid_argument{"Buffer data is too small for an IP packet!"};
    }

    IPPacket::IPPacket(std::span<const std::byte> buf)
    {
        if (buf.size() < MIN_PACKET_SIZE)
            throw std::invalid_argument{"Buffer data is too small for an IP packet!"};

        _buf.resize(buf.size());
        std::memcpy(_buf.data(), buf.data(), buf.size());
    }

    std::span<const std::byte> IPPacket::udp_data()
    {
        auto proto = protocol();
        if (proto != net::IPProtocol::UDP || payload_size() < 8)
            return {};
        return span().subspan(header_size() + 8);
    }

    void IPPacket::clear_addresses()
    {
        if (is_ipv4())
            update_ipv4_address(ipv4{}, ipv4{});
        else if (is_ipv6())
            update_ipv6_address(ipv6{}, ipv6{});
    }

    void IPPacket::update_ipv4_address(const ipv4& src, const ipv4& dst)
    {
        log::trace(logcat, "Setting new source ({}) and destination ({}) IPs", src, dst);

        auto& hdr = header();
        if (auto ihs = hdr.header_size(), sz = size(); ihs <= sz)
        {
            auto* payload = data() + ihs;
            auto payload_size = sz - ihs;
            auto frag_off = size_t(oxenc::big_to_host(hdr.frag_off) & 0x1Fff) * 8;

            auto ip_proto = static_cast<net::IPProtocol>(hdr.protocol);
            switch (ip_proto)
            {
                case net::IPProtocol::TCP:
                    if (frag_off <= TCP_CSUM_OFF && payload_size >= TCP_CSUM_OFF - frag_off + 2)
                    {
                        auto* tcp_hdr = reinterpret_cast<tcp_header*>(payload);
                        tcp_hdr->checksum = update_ipv4_tcp_checksum(tcp_hdr->checksum, hdr.src, hdr.dest, src, dst);
                    }
                    break;
                case net::IPProtocol::UDP:
                case net::IPProtocol::UDP_LITE:  // UDP-Lite - same checksum place, same 0->0xFFff condition
                    if (frag_off <= UDP_CSUM_OFF && payload_size >= UDP_CSUM_OFF + 2)
                    {
                        auto* udp_hdr = reinterpret_cast<udp_header*>(payload);
                        udp_hdr->checksum = update_ipv4_udp_checksum(udp_hdr->checksum, hdr.src, hdr.dest, src, dst);
                    }
                    break;
                default:
                    // do nothing (or not implemented)
                    break;
            }
        }

        hdr.checksum = update_ipv4_checksum(hdr.checksum, hdr.src, hdr.dest, src, dst);

        // set new IP addresses
        hdr.src = oxenc::host_to_big(src.addr);
        hdr.dest = oxenc::host_to_big(dst.addr);
    }

    void IPPacket::update_ipv6_address(const ipv6& src, const ipv6& dst, std::optional<uint32_t> flowlabel)
    {
        const auto sz = size();
        // XXX should've been checked at upper level?
        if (sz <= sizeof(ipv6_header))
            return;

        auto& hdr = v6_header();
        if (flowlabel.has_value())
            hdr.flowlabel(*flowlabel);

        std::array<uint32_t, 4> old_src, old_dest;
        std::memcpy(old_src.data(), hdr.src.s6_addr, 16);
        std::memcpy(old_dest.data(), hdr.dest.s6_addr, 16);
        hdr.src = static_cast<in6_addr>(src);
        hdr.dest = static_cast<in6_addr>(dst);
        std::span<const uint32_t, 4> new_src{reinterpret_cast<const uint32_t*>(hdr.src.s6_addr), 4},
            new_dest{reinterpret_cast<const uint32_t*>(hdr.dest.s6_addr), 4};

        // TODO IPv6 header options
        auto payload = span().subspan<sizeof(ipv6_header)>();

        size_t fragoff = 0;
        auto nextproto = hdr.protocol;
        for (;;)
        {
            switch (nextproto)
            {
                case 0:   // Hop-by-Hop Options
                case 43:  // Routing Header
                case 60:  // Destination Options
                {
                    nextproto = static_cast<uint8_t>(payload[0]);
                    auto addlen = (static_cast<size_t>(payload[1]) + 1) * 8;
                    if (payload.size() < addlen)
                        return;
                    payload = payload.subspan(addlen);
                    break;
                }

                case 44:  // Fragment Header
                    /*
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Identification                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     */
                    nextproto = static_cast<uint8_t>(payload[0]);
                    fragoff = (static_cast<uint16_t>(payload[2]) << 8) | (static_cast<uint16_t>(payload[3]) & 0xFC);
                    if (payload.size() < 8)
                        return;
                    payload = payload.subspan(8);

                    // jump straight to payload processing
                    if (fragoff != 0)
                        goto endprotohdrs;
                    break;

                default:
                    goto endprotohdrs;
            }
        }
    endprotohdrs:

        std::optional<uint16_t> csum_off;
        switch (static_cast<net::IPProtocol>(nextproto))
        {
            case net::IPProtocol::TCP:
                csum_off = TCP_CSUM_OFF;
                break;
            case net::IPProtocol::ICMP6:
                csum_off = ICMP_CSUM_OFF;
                break;
            case net::IPProtocol::UDP:
            case net::IPProtocol::UDP_LITE:
                csum_off = UDP_CSUM_OFF;
                break;
            default:
                // do nothing
                break;
        }
        if (csum_off)
            update_ipv6_proto_checksum(payload, fragoff, *csum_off, old_src, old_dest, new_src, new_dest);
    }

    std::optional<IPPacket> IPPacket::make_icmp_unreachable() const
    {
        if (is_ipv4())
        {
            const auto& header = this->header();
            auto ip_hdr_sz = header.header_size();

            // ICMP unreachable includes a carbon copy of the illiciting packet prefix including *at
            // least* the header, but can also include some of the body: we also include the first
            // 32 bytes after the header.
            std::span orig_prefix{_buf.data(), std::min<size_t>(ip_hdr_sz + 32, _buf.size())};

            size_t pkt_size = sizeof(ip_header) + ICMPv4_HEADER_SIZE + orig_prefix.size();

            IPPacket pkt{pkt_size};

            auto& hdr = pkt.header();
            hdr.version_ihl = 0x45;  // IPv4, 20-byte header with no options
            hdr.service_type = 0;
            hdr.checksum = 0;
            hdr.total_len = ntohs(pkt_size);
            hdr.src = header.dest;
            hdr.dest = header.src;
            hdr.protocol = 1;  // ICMP
            hdr.ttl = header.ttl;
            hdr.frag_off = oxenc::host_to_big<uint16_t>(0b01000000'00000000);

            std::byte* itr = pkt.data() + sizeof(ip_header);
            auto* icmp_begin = itr;
            *itr++ = std::byte{3};  // ICMP type 3 = 'destination unreachable'
            *itr++ = std::byte{1};  // ICMP code 1 = 'host unreachable error'

            // 2 byte checksum (we'll come back to this later)
            auto* checksum = reinterpret_cast<uint16_t*>(itr);
            itr += 2;
            // optional length byte + unused byte + optional 2-byte next hop MTU (for code 4, i.e.
            // not us).  We leave this all as zero (and buf is already 0 initialized).
            itr += (1 + 1 + 2);

            assert(itr == pkt.data() + sizeof(ip_header) + ICMPv4_HEADER_SIZE);

            // carbon copy the original packet prefix:
            std::memcpy(itr, orig_prefix.data(), orig_prefix.size());
            itr += orig_prefix.size();

            assert(itr == pkt.data() + pkt_size);

            // calculate checksum of ip header
            pkt.header().checksum = ip_checksum(reinterpret_cast<const uint8_t*>(pkt.data()), sizeof(ip_header));

            // calculate icmp checksum from everything from icmp header (inclusive) to the end.
            *checksum = ip_checksum(reinterpret_cast<const uint8_t*>(icmp_begin), std::distance(icmp_begin, itr));

            log::debug(logcat, "Constructed ICMP unreachable packet");
            return pkt;
        }

        if (is_ipv6())
        {
            const auto& header = v6_header();

            // ICMP unreachable includes a carbon copy of the illiciting packet prefix including *at
            // least* the header, but can also include some of the body: we also include the first
            // 32 bytes after the header, reduce it to the nearest multiple of 4 if required
            // (because keeping it a multiple of 4 simplifies the checksum calculation).
            std::span orig_prefix{_buf.data(), std::min<size_t>(sizeof(ipv6_header) + 32, _buf.size())};
            if (orig_prefix.size() % 4 != 0)
                orig_prefix = orig_prefix.subspan(0, orig_prefix.size() - (orig_prefix.size() % 4));

            // The +4 here is an unused 32-bit value that precedes the carbon copied incoming packet
            // prefix:
            uint16_t payload_size = ICMPv6_HEADER_SIZE + 4 + orig_prefix.size();

            IPPacket pkt{sizeof(ipv6_header) + payload_size};

            auto& hdr = pkt.v6_header();
            hdr.version(6);
            hdr.payload_len = oxenc::host_to_big(payload_size);
            hdr.protocol = 58;  // ICMPv6
            hdr.hoplimit = header.hoplimit;
            hdr.src = header.dest;
            hdr.dest = header.src;

            std::span<std::byte, 4> icmp_header{pkt.data() + sizeof(hdr), 4};
            icmp_header[0] = std::byte{1};  // ICMPv6 type 1 = 'destination unreachable'
            icmp_header[1] = std::byte{3};  // ICMPv6 code 3 = 'address unreachable'

            // The ICMPv6 body for destination unreachable consists of an unused (all-0) 4-byte
            // value, followed by the carbon copy the original packet prefix after the icmp header:
            std::memcpy(icmp_header.data() + icmp_header.size() + 4, orig_prefix.data(), orig_prefix.size());

            // 2 byte ICMPv6 checksum which checksums the IPv6 header info as well
            *reinterpret_cast<uint16_t*>(&icmp_header[2]) =
                ipv6_proto_checksum(hdr, std::span{pkt.data() + sizeof(hdr), pkt.size() - sizeof(hdr)});

            log::debug(logcat, "Constructed ICMPv6 unreachable packet");
            return pkt;
        }

        return std::nullopt;
    }

    std::vector<std::byte> IPPacket::make_udp_packet(
        const quic::ipv6& src,
        uint16_t src_port,
        const quic::ipv6& dest,
        uint16_t dest_port,
        std::span<const std::byte> payload)
    {
        std::vector<std::byte> pkt;
        pkt.resize(sizeof(ipv6_header) + sizeof(udp_header) + payload.size());
        auto* data = pkt.data();
        auto& ip_hdr = *reinterpret_cast<ipv6_header*>(data);
        data += sizeof(ipv6_header);
        auto& udp_hdr = *reinterpret_cast<udp_header*>(data);
        data += sizeof(udp_header);
        std::memcpy(data, payload.data(), payload.size());

        ip_hdr.version(6);
        ip_hdr.payload_len = oxenc::host_to_big<uint16_t>(sizeof(udp_header) + payload.size());
        ip_hdr.protocol = static_cast<uint8_t>(net::IPProtocol::UDP);
        ip_hdr.hoplimit = 255;

        oxenc::write_host_as_big(src.hi, &ip_hdr.src.s6_addr[0]);
        oxenc::write_host_as_big(src.lo, &ip_hdr.src.s6_addr[8]);
        oxenc::write_host_as_big(dest.hi, &ip_hdr.dest.s6_addr[0]);
        oxenc::write_host_as_big(dest.lo, &ip_hdr.dest.s6_addr[8]);

        udp_hdr.src = oxenc::host_to_big(src_port);
        udp_hdr.dest = oxenc::host_to_big(dest_port);
        udp_hdr.len = oxenc::host_to_big<uint16_t>(payload.size() + sizeof(udp_header));
        udp_hdr.checksum =
            ipv6_proto_checksum(ip_hdr, std::span{pkt.data() + sizeof(ip_hdr), pkt.size() - sizeof(ip_hdr)});

        // UDPv6 special case: if the checksum result is 0x0000 we change it to the equal (under 1's
        // complement) 0xffff value because 0x0000 is a IPv4 special "no checksum" value that is not
        // allowed in UDPv6.
        if (udp_hdr.checksum == 0x0000)
            udp_hdr.checksum = 0xffff;

        return pkt;
    }

    std::string IPPacket::info_printer::to_string() const
    {
        if (pkt.is_ipv4())
        {
            return "IPv4[{}, {}B, src={}, dst={}]"_format(
                ip_protocol_name(pkt.protocol()), pkt.size(), *pkt.source_ipv4(), *pkt.dest_ipv4());
        }
        if (pkt.is_ipv6())
        {
            return "IPv6[{}, {}B, src={}, dst={}]"_format(
                ip_protocol_name(pkt.protocol()), pkt.size(), *pkt.source_ipv6(), *pkt.dest_ipv6());
        }
        return "IPPacket[<unknown-type>, {}B]"_format(pkt.size());
    }

}  // namespace srouter
