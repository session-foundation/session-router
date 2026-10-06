#pragma once

#include "address/map.hpp"
#include "ev/fd_poller.hpp"
#include "handlers/tun_interface.hpp"
#include "net/ip_packet.hpp"
#include "util/thread/threading.hpp"
#include "vpn/packet_router.hpp"
#include "vpn/platform.hpp"

namespace srouter::handlers
{
    inline constexpr auto TUN = "tun"sv;

    class TunEndpoint : public ITunnel
    {
      public:
        TunEndpoint(Router& r);
        ~TunEndpoint();

      private:
        Router& _router;

        /// our local ip network
        ipv4_net _local_net;
        IPv4RangeIterator _local_range_iterator{_local_net};

        ipv6_net _local_ipv6_net;
        IPv6RangeIterator _local_ipv6_range_iterator{_local_ipv6_net};

        /// list of strict connect addresses for hooks
        // std::vector<IpAddress> _strict_connect_addrs;

        std::string _if_name;

        std::shared_ptr<vpn::NetworkInterface> _net_if;
        std::unique_ptr<ev::FDPoller> _poller;

        std::shared_ptr<vpn::PacketRouter> _packet_router;

        std::optional<net::ExitPolicy> _exit_policy = std::nullopt;

        /// a file to load / store the ephemeral address map to
        std::optional<std::filesystem::path> _persisting_addr_file = std::nullopt;
        bool persist_addrs{false};

      public:
        vpn::NetworkInterface* get_vpn_interface() { return _net_if.get(); }

        std::string_view name() const { return TUN; }

        void configure();

        std::string get_if_name() const override;

        // Returns the Session Router tun IPv4 address
        const ipv4& get_ipv4() const;
        // Returns the Session Router tun IPv6 address
        const ipv6& get_ipv6() const;

        // Returns the Session Router tun IPv4/6 network; the address is set to this tun device's
        // local address (i.e. typically the .1 address).
        const ipv4_net& get_ipv4_network() const override;
        const ipv6_net& get_ipv6_network() const override;

        void tick_tun(sys_ms now);

        void stop() override;

        bool is_service_node() const;

        bool is_exit_node() const;

        // INPROGRESS: new API
        // Handles an outbound packet going OUT to the network
        void handle_outbound_packet(IPPacket pkt);

        void rewrite_and_send_packet(IPPacket&& pkt, const ipv4& src, const ipv4& dest);
        void rewrite_and_send_packet(IPPacket&& pkt, const ipv6& src, const ipv6& dest);

        void handle_inbound_packet(IPPacket pkt, traffic_type type, NetworkAddress remote) override;

        // Handles an inbound packet coming IN from the network
        // bool handle_inbound_packet(IPPacket pkt, NetworkAddress remote, bool is_exit_session, bool
        // is_outbound_session);

        // Obtains an available IPv6 address from the tun device and associates the given Session
        // Router remote address with it.  If the mapping already exists, this returns the existing
        // IP, otherwise it assigns a new one.  The association persists until unmapped.  Returns
        // the mapped ipv6 address.
        ipv6 map6(const NetworkAddress& remote) override;

        // Obtains an available IPv4 address from the tun device and associates the given Session
        // Router remote address with it.  If the mapping already exists, this returns the existing
        // IP.  IPv4 addresses are only used for enabling exit traffic, and so this address is
        // typically not mapped until exit mode is enabled; all internal Session Router is carried
        // over IPv6.
        //
        // Returns the mapped addresses, or nullptr if an address could not be assigned (i.e.
        // because of IPv4 exhaustion in the allocated tun range, or because this client does not
        // support IPv4 addressing at all).
        std::optional<ipv4> map4(const NetworkAddress& remote) override;

        // Takes an IPv4 or IPv6 address and returns {addr, true} if the address is a tun address
        // range IP mapped to an address; {nullptr, true} if it is a tun address range IP but
        // without a mapped address; or {nullptr, false} if it is not a tun address range IP.
        std::pair<std::optional<NetworkAddress>, bool> reverse_lookup(const ipv4& ip) override
        {
            return reverse_lookup_impl(ip);
        }
        std::pair<std::optional<NetworkAddress>, bool> reverse_lookup(const ipv6& ip) override
        {
            return reverse_lookup_impl(ip);
        }

        template <typename IP>
        std::pair<std::optional<NetworkAddress>, bool> reverse_lookup_impl(const IP& ip)
            requires std::same_as<IP, ipv4> || std::same_as<IP, ipv6>
        {
            std::pair<std::optional<NetworkAddress>, bool> result;
            auto& [netaddr, in_range] = result;
            if constexpr (std::same_as<IP, ipv4>)
            {
                netaddr = _local_ipv4_mapping[ip];
                in_range = netaddr || _local_net.contains(ip);
            }
            else
            {
                netaddr = _local_ipv6_mapping[ip];
                in_range = netaddr || _local_ipv6_net.contains(ip);
            }
            return result;
        }

        // Expires a mapped IP for the given remote from the tun IP map.  The address will be added
        // as the most recently used address, and (if the configured cache size is exceeded) the least
        // recently used address will be forgotten.
        void expire(const NetworkAddress& remote) override;

        std::optional<net::ExitPolicy> get_exit_policy() const { return _exit_policy; }

        /// ip packet against any exit policies we have
        /// returns false if this traffic is disallowed by any of those policies
        /// returns true otherwise
        bool is_allowing_traffic(const IPPacket& pkt) const;

        std::pair<std::optional<ipv4>, std::optional<ipv6>> get_mapped_ip(const NetworkAddress& addr);

        const Router& router() const { return _router; }

        Router& router() { return _router; }

        void start_poller() override;

      private:
        // Stores assigned IP's for each session in/out of this Session Router instance
        //  - Reserved local addresses are directly pre-loaded from config
        //  - Persisting address map is directly pre-loaded from config
        address_map<ipv4> _local_ipv4_mapping;
        address_map<ipv6> _local_ipv6_mapping;

        // We keep a list of expired network addresses ordered by least-recently-used first.  When
        // pruning the expired list, we pop off the front of the list.
        std::list<NetworkAddress> _expired;
        // Maps a NetworkAddress to its iterator in `_expired` so that if an expired address gets
        // reused, we can find it and extract it to move it to the end.
        std::unordered_map<NetworkAddress, std::list<NetworkAddress>::iterator> _exp_it;

        // Checks the _expired cache and, if too big, prunes the oldest entries.
        void prune_expired();

        // Returns the next available unused IPv4 address from the local tun network
        std::optional<ipv4> get_next_local_ipv4();

        // Returns a local tun IPv6 address for the given remote.  If available, the leading prefix
        // of the remote address is used within the local tun IPv6 range; if that is already used or
        // invalid then the next available sequential address is used (as in IPv4 allocation).
        std::optional<ipv6> get_next_local_ipv6(const NetworkAddress& remote);

        std::optional<ipv4> obtain_src_for_ipv4_remote(const NetworkAddress& remote);
        std::optional<ipv6> obtain_src_for_ipv6_remote(const NetworkAddress& remote);

        void send_packet_to_net_if(IPPacket pkt);
    };

}  // namespace srouter::handlers
