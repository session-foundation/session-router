#pragma once

#include "ip_headers.hpp"
#include "policy.hpp"
#include "traffic_type.hpp"
#include "util/formattable.hpp"
#include "util/time.hpp"

#include <oxen/quic/address.hpp>
#include <oxen/quic/udp.hpp>
#include <oxenc/endian.h>

namespace srouter
{
    inline constexpr size_t MAX_PACKET_SIZE{1500};
    inline constexpr size_t MIN_PACKET_SIZE{20};

    struct IPPacket;

    using net_pkt_hook = std::function<void(quic::Packet&& pkt)>;
    using ip_pkt_hook = std::function<void(IPPacket)>;

    /** IPPacket
        This class encapsulates the functionalities and attributes required for data transmission between the local
        Session Router instance and the surrounding IP landscape. As data enters Session Router from the
       device/internet/etc, it is transmitted across the network as a quic::Packet via QUIC. As it exits Session Router
       to the device/internet/etc, it is constructed into an IPPacket.

        This allows for necessary functionalities at the junction that data is entering and exiting the local Session
       Router instance. For example

    */
    struct IPPacket
    {
      private:
        std::vector<std::byte> _buf;

      public:
        IPPacket() : IPPacket{size_t{0}} {}
        explicit IPPacket(size_t sz);
        explicit IPPacket(std::vector<std::byte>&& data);
        explicit IPPacket(std::span<const std::byte> buf);

        // Is this gross thing really needed?
        static std::optional<IPPacket> try_making(std::span<const std::byte> buf);

        ip_header& header() { return *reinterpret_cast<ip_header*>(data()); }
        const ip_header& header() const { return *reinterpret_cast<const ip_header*>(data()); }

        ipv6_header& v6_header() { return *reinterpret_cast<ipv6_header*>(data()); }
        const ipv6_header& v6_header() const { return *reinterpret_cast<const ipv6_header*>(data()); }

        size_t header_size() const
        {
            return is_ipv4() ? static_cast<size_t>(header().header_len) * 4 : is_ipv6() ? 40 : 0;
        }
        size_t payload_size() const
        {
            auto hsz = header_size();
            return hsz >= _buf.size() ? 0 : _buf.size() - hsz;
        }

        bool is_ipv4() const { return _buf.size() >= sizeof(ip_header) && header().version == 4; }
        bool is_ipv6() const { return _buf.size() >= sizeof(ipv6_header) && v6_header().version == 6; }
        bool is_ip() const { return is_ipv4() || is_ipv6(); }

        net::IPProtocol protocol() const
        {
            return is_ipv4() ? net::IPProtocol{header().protocol}
                : is_ipv6()  ? net::IPProtocol{v6_header().protocol}
                             : net::IPProtocol{};
        }

      private:
        std::optional<uint16_t> _s_d_port(int offset) const
        {
            auto pr = protocol();
            if (pr == net::IPProtocol::TCP || pr == net::IPProtocol::UDP)
                if (auto hs = header_size(); _buf.size() >= hs + 4)
                    return oxenc::load_big_to_host<uint16_t>(_buf.data() + hs + offset);
            return std::nullopt;
        }

      public:
        std::optional<uint16_t> source_port() const { return _s_d_port(0); }
        std::optional<uint16_t> dest_port() const { return _s_d_port(2); }

        std::optional<ipv4> source_ipv4() const
        {
            if (is_ipv4())
                return ipv4{oxenc::big_to_host(header().src)};
            return std::nullopt;
        }
        std::optional<ipv4> dest_ipv4() const
        {
            if (is_ipv4())
                return ipv4{oxenc::big_to_host(header().dest)};
            return std::nullopt;
        }

        std::optional<ipv6> source_ipv6() const
        {
            if (is_ipv6())
                return ipv6{v6_header().src};
            return std::nullopt;
        }
        std::optional<ipv6> dest_ipv6() const
        {
            if (is_ipv6())
                return ipv6{v6_header().dest};
            return std::nullopt;
        }

        std::span<const std::byte> udp_data();

        void clear_addresses();

        void update_ipv4_address(const ipv4& src, const ipv4& dst);

        void update_ipv6_address(const ipv6& src, const ipv6& dst, std::optional<uint32_t> flowlabel = std::nullopt);

        std::optional<IPPacket> make_icmp_unreachable() const;

        static std::vector<std::byte> make_udp_packet(
            const quic::ipv6& src,
            uint16_t src_port,
            const quic::ipv6& dest,
            uint16_t dest_port,
            std::span<const std::byte> payload);

        std::byte* data() { return _buf.data(); }
        const std::byte* data() const { return _buf.data(); }

        size_t size() const { return _buf.size(); }

        std::span<std::byte> span() { return _buf; }
        std::span<const std::byte> span() const { return _buf; }

        bool empty() const { return _buf.empty(); }

        // Lightweight formattable proxy object:
        struct info_printer
        {
            const IPPacket& pkt;
            std::string to_string() const;
            static constexpr bool to_string_formattable = true;
        };

        info_printer info_line() const { return {*this}; }
    };

}  // namespace srouter
