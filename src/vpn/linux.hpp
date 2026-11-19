#pragma once

#include "common.hpp"
#include "platform.hpp"
#include "router/router.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <oxenc/endian.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <unordered_map>

namespace srouter::vpn
{
    static auto logcat = log::Cat("vpn.linux");

    // Route protocol number put on every route we add, so that routes left behind by a run that
    // didn't shut down cleanly can be found and removed at the next start (see
    // delete_stale_routes), and so that our deletes never remove somebody else's identical route.
    // Values above RTPROT_STATIC aren't interpreted by the kernel.
    inline constexpr uint8_t RTPROT_SROUTER = 212;

    // Interface kinds (IFLA_INFO_KIND) that are tunnels or overlays, never the uplink.
    inline constexpr std::array<std::string_view, 21> TUNNEL_KINDS{
        "wireguard", "tun", "tap",  "sit",  "ipip",   "ip6tnl", "gre",     "gretap", "ip6gre", "ip6gretap", "erspan",
        "ip6erspan", "vti", "vti6", "xfrm", "geneve", "vxlan",  "bareudp", "amt",    "ipvlan", "macsec"};

    // Names VPN clients commonly give their interfaces.
    inline constexpr std::array<std::string_view, 10> TUNNEL_NAMES{
        "wg", "tun", "tap", "tailscale", "mullvad", "utun", "nordlynx", "proton", "zt", "ipsec"};

    // Real uplinks that are point-to-point or have no link-layer header (PPP, PPPoE, cellular
    // modems).  Never treated as tunnels, whatever their kind says.
    inline constexpr std::array<std::string_view, 6> UPLINK_NAMES{"ppp", "wwan", "rmnet", "usb", "mbim", "qmi"};

    // Whether an interface is a VPN or overlay tunnel (or loopback) rather than a possible uplink.
    // The point-to-point flag and a missing link-layer header are deliberately not used: PPP and
    // raw-IP cellular modems have both and are real uplinks.
    inline bool is_tunnel_link(std::string_view name, std::string_view kind, bool loopback)
    {
        auto prefixed = [name](const auto& list) {
            return std::ranges::any_of(list, [name](std::string_view p) { return name.starts_with(p); });
        };
        if (loopback)
            return true;
        if (prefixed(UPLINK_NAMES))
            return false;
        if (std::ranges::find(TUNNEL_KINDS, kind) != TUNNEL_KINDS.end())
            return true;
        // tun/tap devices have this whatever they are called.
        if (not name.empty() and access("/sys/class/net/{}/tun_flags"_format(name).c_str(), F_OK) == 0)
            return true;
        return prefixed(TUNNEL_NAMES);
    }

    struct in6_ifreq
    {
        in6_addr addr;
        uint32_t prefixlen;
        unsigned int ifindex;
    };

    struct call_on_destroy
    {
        std::function<void()> f;
        ~call_on_destroy()
        {
            if (f)
                f();
        }
        void disarm() { f = nullptr; }
    };

    // Send a netlink request and wait for its ACK.  Returns 0 on success, otherwise the errno value
    // the kernel (or send/recv) reported.  Must have set NLM_F_ACK on the request header flags!
    // Replies whose sequence number does not match the request are skipped.
    template <typename NLRequestT>
    int nl_submit_errno(int nlfd, const NLRequestT& req)
    {
        assert(req.header.nlmsg_flags & NLM_F_REQUEST);
        assert(req.header.nlmsg_flags & NLM_F_ACK);
        log::trace(logcat, "submitting netlink request to fd {}", nlfd);
        if (-1 == send(nlfd, &req, req.header.nlmsg_len, 0))
            return errno;

        alignas(nlmsghdr) char resp_buf[8192];
        for (;;)
        {
            log::trace(logcat, "waiting for netlink response");
            auto resp_len = recv(nlfd, resp_buf, sizeof(resp_buf), 0);
            if (resp_len < 0)
            {
                if (errno == EINTR)
                    continue;
                return errno;
            }
            log::trace(logcat, "got netlink response");
            auto len = static_cast<unsigned int>(resp_len);
            for (auto* resp = reinterpret_cast<nlmsghdr*>(resp_buf); NLMSG_OK(resp, len); resp = NLMSG_NEXT(resp, len))
            {
                if (resp->nlmsg_seq != req.header.nlmsg_seq)
                    continue;
                if (resp->nlmsg_type != NLMSG_ERROR)
                    return EPROTO;
                auto* nlerr = static_cast<nlmsgerr*>(NLMSG_DATA(resp));
                return nlerr->error < 0 ? -nlerr->error : 0;
            }
        }
    }

    // Send a netlink request and wait for the response.  Returns an error string on error, nullopt
    // on success.  Must have set NLM_F_ACK on the request header flags!
    template <typename NLRequestT>
    std::optional<std::string> nl_submit(int nlfd, const NLRequestT& req)
    {
        if (int err = nl_submit_errno(nlfd, req))
            return strerror(err);
        return std::nullopt;
    }

    class LinuxInterface : public NetworkInterface
    {
        const int _fd;

      public:
        LinuxInterface(InterfaceInfo info) : NetworkInterface{std::move(info)}, _fd{::open("/dev/net/tun", O_RDWR)}
        {
            if (_fd == -1)
                throw std::runtime_error("cannot open /dev/net/tun {}"_format(strerror(errno)));

            call_on_destroy fd_abort{[fd = _fd] { close(fd); }};

            if (fcntl(_fd, F_SETFL, O_NONBLOCK) == -1)
                throw std::runtime_error{
                    "Failed to set `O_NONBLOCK` on Linux interface FD: {}"_format(strerror(errno))};

            ifreq ifr{};
            ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
            std::memcpy(ifr.ifr_name, _info.ifname.c_str(), std::min<size_t>(_info.ifname.size(), IFNAMSIZ - 1));

            log::debug(logcat, "Setting interface name to '{}'", _info.ifname);
            if (::ioctl(_fd, TUNSETIFF, &ifr) == -1)
                throw std::runtime_error{"Cannot set TUN interface name: {}"_format(strerror(errno))};

            // The ioctl above could have changed the tun device on us:
            _info.ifname = ifr.ifr_name;
            _info.index = if_nametoindex(_info.ifname.c_str());

            log::debug(logcat, "Set interface name to '{}'.  Adding adresses", _info.ifname);

            int nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
            if (nlfd == -1)
                throw std::runtime_error{"netlink failed: {}"_format(strerror(errno))};
            call_on_destroy nlfd_cleanup([nlfd] { close(nlfd); });

            if (_info.addrs.empty())
                throw std::runtime_error{"Cannot set up a TUN interface with no addresses!"};

            auto net_plat = srouter::net::Platform::Default_ptr();
            assert(net_plat);

            std::list<std::string> addr_strings;

            // Counts the number of consecutive failures to apply an auto-selected unused range
            int auto_failures = 0;

            // Add addresses to the tun interface:
            for (auto it = _info.addrs.begin(); it != _info.addrs.end();)
            {
                auto& ifaddr = *it;
                struct
                {
                    nlmsghdr header;
                    ifaddrmsg content;
                    char buf[256];
                } request{};
                size_t buf_avail = sizeof(request.buf);

                request.header.nlmsg_len = NLMSG_LENGTH(sizeof request.content);
                request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE | NLM_F_ACK;
                request.header.nlmsg_type = RTM_NEWADDR;
                request.content.ifa_index = _info.index;

                const ipv4_net* n4 = std::get_if<ipv4_net>(&ifaddr);
                const ipv6_net* n6 = nullptr;

                std::optional<std::variant<ipv4_net, ipv6_net>> auto_addr;
                if (n4)
                {
                    if (n4->ip == ipv4{})
                    {  // "0" IP means auto-select a free range
                        auto n = net_plat->find_free_ipv4_net(n4->mask);
                        if (!n)
                            throw std::runtime_error{
                                "Could not find any unused private IPv4 /{} range for auto-selection"_format(n4->mask)};

                        auto_addr = std::move(*n);
                        n4 = &std::get<ipv4_net>(*auto_addr);
                    }

                    addr_strings.push_back(n4->to_string());
                    request.content.ifa_family = AF_INET;
                    request.content.ifa_prefixlen = n4->mask;
                    auto* req_attr = IFA_RTA(&request.content);
                    req_attr->rta_type = IFA_LOCAL;
                    req_attr->rta_len = RTA_LENGTH(sizeof(in_addr));
                    request.header.nlmsg_len += req_attr->rta_len;
                    oxenc::write_host_as_big(n4->ip.addr, RTA_DATA(req_attr));

                    req_attr = RTA_NEXT(req_attr, buf_avail);
                    req_attr->rta_type = IFA_ADDRESS;
                    req_attr->rta_len = RTA_LENGTH(sizeof(in_addr));
                    request.header.nlmsg_len += req_attr->rta_len;
                    oxenc::write_host_as_big(n4->ip.addr, RTA_DATA(req_attr));
                }
                else
                {
                    n6 = &std::get<ipv6_net>(ifaddr);
                    if (n6->ip == ipv6{})
                    {  // "0" IP means auto-select a free range
                        auto n = net_plat->find_free_ipv6_net(n6->mask);
                        if (!n)
                            throw std::runtime_error{
                                "Could not find any unused private IPv6 /{} range for auto-selection"_format(n6->mask)};

                        auto_addr = std::move(*n);
                        n6 = &std::get<ipv6_net>(*auto_addr);
                    }

                    addr_strings.push_back(n6->to_string());
                    request.content.ifa_family = AF_INET6;
                    request.content.ifa_prefixlen = n6->mask;
                    auto* req_attr = IFA_RTA(&request.content);
                    req_attr->rta_type = IFA_LOCAL;
                    req_attr->rta_len = RTA_LENGTH(sizeof(in6_addr));
                    request.header.nlmsg_len += req_attr->rta_len;
                    char* addr_data = static_cast<char*>(RTA_DATA(req_attr));
                    oxenc::write_host_as_big(n6->ip.hi, addr_data);
                    oxenc::write_host_as_big(n6->ip.lo, addr_data + 8);

                    req_attr = RTA_NEXT(req_attr, buf_avail);
                    req_attr->rta_type = IFA_ADDRESS;
                    req_attr->rta_len = RTA_LENGTH(sizeof(in6_addr));
                    request.header.nlmsg_len += req_attr->rta_len;
                    addr_data = static_cast<char*>(RTA_DATA(req_attr));
                    oxenc::write_host_as_big(n6->ip.hi, addr_data);
                    oxenc::write_host_as_big(n6->ip.lo, addr_data + 8);
                }

                if (auto err = nl_submit(nlfd, request))
                    throw std::runtime_error{
                        "Failed to add address {} to {}: {}"_format(addr_strings.back(), _info.ifname, *err)};

                // Adding a conflicting address does not fail, and so we need to go query all the
                // addresses on the system to see if the same address exists on any *other*
                // interface and if so, either retry (if we are using auto-selection) or error out.

                ifaddrs* ia_head;
                if (0 != getifaddrs(&ia_head))
                    throw std::runtime_error{"Failed to query network addresses to check for duplicates"};

                std::string problem;
                for (ifaddrs* ia = ia_head; ia && problem.empty(); ia = ia->ifa_next)
                {
                    if (ia->ifa_name == _info.ifname)
                        continue;  // This is our own one that we just added

                    if (!ia->ifa_addr)
                        continue;  // Dunno

                    if (n4 && ia->ifa_addr->sa_family == AF_INET)
                    {
                        ipv4 found4{reinterpret_cast<sockaddr_in*>(ia->ifa_addr)->sin_addr};
                        if (n4->contains(found4))
                            problem =
                                "TUN setup {} with address {} failed: found conflicting IP {} on network interface {}"_format(
                                    _info.ifname, *n4, found4, ia->ifa_name);
                    }
                    else if (n6 && ia->ifa_addr && ia->ifa_addr->sa_family == AF_INET6)
                    {
                        ipv6 found6{reinterpret_cast<sockaddr_in6*>(ia->ifa_addr)->sin6_addr};
                        if (n6->contains(found6))
                            problem =
                                "TUN setup {} @ {} failed: found conflicting IP {} on network interface {}"_format(
                                    _info.ifname, *n6, found6, ia->ifa_name);
                    }
                }
                freeifaddrs(ia_head);

                if (!problem.empty())
                {
                    if (auto_addr && auto_failures++ < 50)
                    {
                        log::warning(
                            logcat,
                            "Address auto-selection failure: {}; removing address and retrying auto-selection",
                            problem);

                        // The request to delete the address is identical, aside from the nlmsg_type and flags:
                        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
                        request.header.nlmsg_type = RTM_DELADDR;
                        if (auto err = nl_submit(nlfd, request))
                            throw std::runtime_error{"Failed to delete address {} from {}: {}"_format(
                                addr_strings.back(), _info.ifname, *err)};

                        addr_strings.pop_back();

                        // We add a tiny random delay here so that if we are racing with another SR
                        // process trying to auto-select a range we are more likely to have one or
                        // the other succeed and "win" a range without getting both stuck racing
                        // again trying to use the same address again on the next iteration.
                        std::this_thread::sleep_for(
                            uniform_duration_distribution<std::chrono::nanoseconds>{0ms, 25ms}(csrng));

                        continue;  // *Without* it++
                    }

                    throw std::runtime_error{problem};
                }

                if (auto_addr)
                {
                    log::info(logcat, "Auto-selected tun range {}", addr_strings.back());
                    ifaddr = std::move(*auto_addr);
                    auto_failures = 0;  // Reset in case the next address also needs auto-selection
                }

                ++it;
            }

            // Bring up the tun device:
            {
                struct
                {
                    nlmsghdr header;
                    ifinfomsg content;
                } request{};
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof request.content);
                request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
                request.header.nlmsg_type = RTM_NEWLINK;
                request.content.ifi_index = static_cast<int>(_info.index);
                request.content.ifi_flags = IFF_UP;
                request.content.ifi_change = 1;

                if (auto err = nl_submit(nlfd, request))
                    throw std::runtime_error{"Failed to bring up tun device {}: {}"_format(_info.ifname, *err)};
            }

            fd_abort.disarm();
            log::info(logcat, "TUN device {} now up with address(es): {}", _info.ifname, fmt::join(addr_strings, ", "));
        }

        ~LinuxInterface() override { ::close(_fd); }

        int PollFD() const override { return _fd; }

        IPPacket read_next_packet() override
        {
            std::vector<std::byte> buf;
            buf.resize(MAX_PACKET_SIZE);
            const auto sz = read(_fd, buf.data(), buf.capacity());
            // log::trace(logcat, "{} bytes read from fd {} (err?:{})", sz, _fd, strerror(errno));
            if (sz < 0)
            {
                if (errno == EAGAIN or errno == EWOULDBLOCK)
                {
                    errno = 0;
                    return IPPacket{};
                }
                throw std::error_code{errno, std::system_category()};
            }

            buf.resize(sz);
            return IPPacket{std::move(buf)};
        }

        bool write_packet(IPPacket pkt) override
        {
            const auto sz = write(_fd, pkt.data(), pkt.size());
            // log::trace(logcat, "{} bytes written to fd {} (err?:{})", sz, _fd, strerror(errno));
            if (sz <= 0)
                return false;
            return sz == static_cast<ssize_t>(pkt.size());
        }
    };

    class LinuxRouteManager : public AbstractRouteManager
    {
        const int fd;
        uint32_t seq = 0;

        // Where each discovered default gateway is: the interface index, so that host routes via
        // a link-local (e.g. fe80::1) IPv6 gateway can name the device the kernel needs, and
        // whether the default route has no gateway at all (`default dev ppp0`).  Gateway-less
        // uplinks are keyed by one of the interface's own addresses, which stands in for the
        // gateway in the generic code; host routes then go straight out of the device.
        struct gw_info
        {
            int ifindex;
            bool device_only;
        };
        std::unordered_map<ipv4, gw_info> gw_info4;
        std::unordered_map<ipv6, gw_info> gw_info6;

        enum class GatewayMode
        {
            FirstHop,  // Selector for a first-hop route, i.e. for route poking
            Default,   // Selector for default routing, i.e. for global exit traffic routing
        };

        struct NLRequest
        {
            nlmsghdr header;
            rtmsg r;
            char buf[4096];

            void AddData(int type, const void* data, int alen)
            {
#define NLMSG_TAIL(nmsg) ((struct rtattr*)(((intptr_t)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

                int len = RTA_LENGTH(alen);
                rtattr* rta;
                if (NLMSG_ALIGN(header.nlmsg_len) + RTA_ALIGN(len) > sizeof(*this))
                {
                    throw std::length_error{"nlrequest add data overflow"};
                }
                rta = NLMSG_TAIL(&header);
                rta->rta_type = type;
                rta->rta_len = len;
                if (alen)
                {
                    memcpy(RTA_DATA(rta), data, alen);
                }
                header.nlmsg_len = NLMSG_ALIGN(header.nlmsg_len) + RTA_ALIGN(len);
#undef NLMSG_TAIL
            }
        };

        // Submits the request and waits for the kernel's ACK; returns 0 or the errno value.
        int submit(NLRequest& req)
        {
            req.header.nlmsg_flags |= NLM_F_ACK;
            req.header.nlmsg_seq = ++seq;
            return nl_submit_errno(fd, req);
        }

        // Adding something that is already there, or deleting something that is already gone, is
        // not an error for our purposes.
        static bool benign(int cmd, int err)
        {
            return err == 0 or (cmd == RTM_NEWROUTE and err == EEXIST) or (cmd == RTM_DELROUTE and err == ESRCH);
        }

        void make_blackhole(int cmd, int flags, int af)
        {
            // The blackhole goes in the main table, not local: when the local and main tables are
            // not merged (IPv6 always, IPv4 as soon as any custom `ip rule` exists) the local table
            // is consulted first, so a /0 blackhole there would swallow every main-table route,
            // including the routes via the TUN and the first-hop host routes.  In main it only
            // catches what no more specific route covers.
            NLRequest nl_request{};
            nl_request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
            nl_request.header.nlmsg_flags = NLM_F_REQUEST | flags;
            nl_request.header.nlmsg_type = cmd;
            nl_request.header.nlmsg_pid = getpid();
            nl_request.r.rtm_family = af;
            nl_request.r.rtm_table = RT_TABLE_MAIN;
            nl_request.r.rtm_type = RTN_BLACKHOLE;
            nl_request.r.rtm_protocol = RTPROT_SROUTER;
            nl_request.r.rtm_scope = RT_SCOPE_UNIVERSE;
            if (af == AF_INET)
            {
                // Metric 0, like a default route added without one.  Routes with the same prefix
                // and metric are tried in list order, and an add without NLM_F_EXCL or
                // NLM_F_APPEND goes to the front (`ip route prepend`), so the blackhole wins over
                // an existing metric 0 default instead of being rejected.  EEXIST only comes back
                // if the same blackhole is already there.
                ipv4 addr{};
                nl_request.AddData(RTA_DST, &addr.addr, sizeof(addr.addr));
            }
            else
            {
                // IPv6 treats metric 0 as 1024 (the usual default route metric), so use 1.
                uint32_t prio = 1;
                nl_request.AddData(RTA_PRIORITY, &prio, sizeof(prio));
                std::array<uint64_t, 2> addr{};
                nl_request.AddData(RTA_DST, &addr, sizeof(addr));
            }
            if (int err = submit(nl_request); not benign(cmd, err))
                log::warning(
                    logcat,
                    "Failed to {} IPv{} blackhole route: {}",
                    cmd == RTM_NEWROUTE ? "add" : "remove",
                    af == AF_INET ? 4 : 6,
                    strerror(err));
        }

        NLRequest init_route_cmd(int cmd, int flags)
        {
            NLRequest nl_request{};
            /* Initialize request structure */
            nl_request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
            nl_request.header.nlmsg_flags = NLM_F_REQUEST | flags;
            nl_request.header.nlmsg_type = cmd;
            nl_request.header.nlmsg_pid = getpid();
            nl_request.r.rtm_table = RT_TABLE_MAIN;
            // RT_SCOPE_NOWHERE acts as a wildcard when deleting, but the kernel rejects it with
            // EINVAL ("Invalid scope") when adding a route, so new routes default to universe scope.
            nl_request.r.rtm_scope = RT_SCOPE_NOWHERE;
            // On deletes this restricts the match to our own routes.
            nl_request.r.rtm_protocol = RTPROT_SROUTER;

            /* Set additional flags if NOT deleting route */
            if (cmd != RTM_DELROUTE)
            {
                nl_request.r.rtm_type = RTN_UNICAST;
                nl_request.r.rtm_scope = RT_SCOPE_UNIVERSE;
            }

            return nl_request;
        }

        // Default mode routes go out of interface `if_idx` with no gateway.  FirstHop routes go via
        // `gw`, and out of `if_idx` when it is non-zero.
        int route_cmd(int cmd, int flags, const ipv4_range& dst, const ipv4& gw, GatewayMode mode, int if_idx)
        {
            auto nl_request = init_route_cmd(cmd, flags);

            nl_request.r.rtm_family = AF_INET;
            if (mode == GatewayMode::Default and cmd != RTM_DELROUTE)
                nl_request.r.rtm_scope = RT_SCOPE_LINK;
            nl_request.r.rtm_dst_len = dst.mask;

            char gwbuf[4], ipbuf[4];
            oxenc::write_host_as_big(gw.addr, gwbuf);
            oxenc::write_host_as_big(dst.ip.addr, ipbuf);
            if (mode == GatewayMode::FirstHop)
                nl_request.AddData(RTA_GATEWAY, gwbuf, sizeof(gwbuf));
            nl_request.AddData(RTA_DST, ipbuf, sizeof(ipbuf));
            if (if_idx)
                nl_request.AddData(RTA_OIF, &if_idx, sizeof(if_idx));

            return submit(nl_request);
        }

        int route_cmd(int cmd, int flags, const ipv6_range& dst, const ipv6& gw, GatewayMode mode, int if_idx)
        {
            auto nl_request = init_route_cmd(cmd, flags);
            nl_request.r.rtm_family = AF_INET6;
            nl_request.r.rtm_dst_len = dst.mask;

            char gwbuf[16], ipbuf[16];
            oxenc::write_host_as_big(gw.hi, gwbuf);
            oxenc::write_host_as_big(gw.lo, gwbuf + 8);
            oxenc::write_host_as_big(dst.ip.hi, ipbuf);
            oxenc::write_host_as_big(dst.ip.lo, ipbuf + 8);
            // Routes via our own interface go by interface only: the kernel refuses a local
            // address as an IPv6 gateway (EINVAL, "Gateway can not be a local address").
            if (mode == GatewayMode::FirstHop)
                nl_request.AddData(RTA_GATEWAY, gwbuf, sizeof(gwbuf));
            nl_request.AddData(RTA_DST, ipbuf, sizeof(ipbuf));
            if (if_idx)
                nl_request.AddData(RTA_OIF, &if_idx, sizeof(if_idx));

            return submit(nl_request);
        }

        // For routes via the TUN.  These are added with NLM_F_EXCL and removed by us, so EEXIST
        // means someone else (another VPN, say) already has a route to the same prefix with the
        // same metric, and traffic would go their way instead: treat it as a failure.
        static void check(int cmd, int err, std::string_view what)
        {
            if (err == 0 or (cmd == RTM_DELROUTE and err == ESRCH))
                return;
            auto msg = "Failed to {} {}: {}{}"_format(
                cmd == RTM_NEWROUTE ? "add" : "remove",
                what,
                strerror(err),
                err == EEXIST ? " (another route to it already exists)" : "");
            if (cmd == RTM_NEWROUTE)
                throw std::runtime_error{msg};
            log::warning(logcat, "{}", msg);
        }

        void route_all_via_interface(NetworkInterface& vpn, int cmd, int flags)
        {
            const auto& info = vpn.interface_info();

            for (const auto& range : {ipv4{0, 0, 0, 0} / 1, ipv4{128, 0, 0, 0} / 1})
                check(
                    cmd,
                    route_cmd(cmd, flags, range, ipv4{}, GatewayMode::Default, info.index),
                    "default route via TUN");

            if (Net().get_interface_ipv6(info.ifname))
                for (uint16_t nibble : {0x0000, 0x4000, 0x8000, 0xc000})
                    check(
                        cmd,
                        route_cmd(cmd, flags, ipv6{nibble} / 2, ipv6{}, GatewayMode::Default, info.index),
                        "IPv6 default route via TUN");
        }

        template <typename Range>
        void route_range_via_interface(int cmd, int flags, NetworkInterface& vpn, Range range)
        {
            using IP = std::remove_cvref_t<decltype(range.ip)>;
            check(
                cmd,
                route_cmd(cmd, flags, range, IP{}, GatewayMode::Default, vpn.interface_info().index),
                "route to {} via TUN"_format(range));
        }

        template <typename IP>
        void route_via_gateway(int cmd, int flags, IP dest, IP gateway)
        {
            constexpr uint8_t bits = std::same_as<IP, ipv4> ? 32 : 128;
            int if_idx = 0;
            auto mode = GatewayMode::FirstHop;
            auto& info = [this]() -> auto& {
                if constexpr (std::same_as<IP, ipv4>)
                    return gw_info4;
                else
                    return gw_info6;
            }();
            if (auto it = info.find(gateway); it != info.end())
            {
                if_idx = it->second.ifindex;
                // No gateway: straight out of the device, like a route via the TUN.
                if (it->second.device_only)
                    mode = GatewayMode::Default;
            }
            int err = route_cmd(cmd, flags, dest / bits, gateway, mode, if_idx);
            if (benign(cmd, err))
                return;
            auto msg = "Failed to {} route to {} via {}: {}"_format(
                cmd == RTM_NEWROUTE ? "add" : "remove", dest, gateway, strerror(err));
            // A host route that didn't go in must not be counted as pinned, so adds throw.
            if (cmd == RTM_NEWROUTE)
                throw std::runtime_error{msg};
            log::warning(logcat, "{}", msg);
        }

        // Sends a dump request on its own socket and calls `f` with each reply message until the
        // kernel says it's done.  Returns 0 or an errno value.
        template <typename Req, typename F>
        static int nl_dump(Req& req, F&& f)
        {
            int nlfd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
            if (nlfd == -1)
                return errno;
            call_on_destroy closer{[nlfd] { close(nlfd); }};
            timeval tv{.tv_sec = 2, .tv_usec = 0};
            setsockopt(nlfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            req.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            req.header.nlmsg_seq = 1;
            if (-1 == send(nlfd, &req, req.header.nlmsg_len, 0))
                return errno;

            alignas(nlmsghdr) static thread_local char buf[32768];
            for (;;)
            {
                auto got = recv(nlfd, buf, sizeof(buf), 0);
                if (got < 0)
                {
                    if (errno == EINTR)
                        continue;
                    return errno;
                }
                auto len = static_cast<unsigned int>(got);
                for (auto* h = reinterpret_cast<nlmsghdr*>(buf); NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
                {
                    if (h->nlmsg_seq != req.header.nlmsg_seq)
                        continue;
                    if (h->nlmsg_type == NLMSG_DONE)
                        return 0;
                    if (h->nlmsg_type == NLMSG_ERROR)
                    {
                        auto* e = static_cast<nlmsgerr*>(NLMSG_DATA(h));
                        return e->error < 0 ? -e->error : EPROTO;
                    }
                    f(h);
                }
            }
        }

        struct link_state
        {
            std::string name;
            bool usable;  // up, has carrier, and not a tunnel or loopback
        };

        static std::unordered_map<int, link_state> dump_links()
        {
            std::unordered_map<int, link_state> links;
            struct
            {
                nlmsghdr header;
                ifinfomsg content;
            } req{};
            req.header.nlmsg_len = NLMSG_LENGTH(sizeof req.content);
            req.header.nlmsg_type = RTM_GETLINK;
            req.content.ifi_family = AF_UNSPEC;
            int err = nl_dump(req, [&links](nlmsghdr* h) {
                if (h->nlmsg_type != RTM_NEWLINK)
                    return;
                auto* ifi = static_cast<ifinfomsg*>(NLMSG_DATA(h));
                std::string name, kind;
                int len = IFLA_PAYLOAD(h);
                for (auto* a = IFLA_RTA(ifi); RTA_OK(a, len); a = RTA_NEXT(a, len))
                {
                    if (a->rta_type == IFLA_IFNAME)
                        name = static_cast<const char*>(RTA_DATA(a));
                    else if (a->rta_type == IFLA_LINKINFO)
                    {
                        int ilen = RTA_PAYLOAD(a);
                        for (auto* i = static_cast<rtattr*>(RTA_DATA(a)); RTA_OK(i, ilen); i = RTA_NEXT(i, ilen))
                            if (i->rta_type == IFLA_INFO_KIND)
                                kind = static_cast<const char*>(RTA_DATA(i));
                    }
                }
                // IFF_LOWER_UP lives in <linux/if.h>, which clashes with <net/if.h>.
                constexpr unsigned lower_up = 1 << 16;
                const auto fl = ifi->ifi_flags;
                bool up = (fl & IFF_UP) and (fl & (IFF_RUNNING | lower_up));
                bool loopback = (fl & IFF_LOOPBACK) or ifi->ifi_type == ARPHRD_LOOPBACK;
                links[ifi->ifi_index] = {name, up and not is_tunnel_link(name, kind, loopback)};
            });
            if (err)
                log::warning(logcat, "Failed to list network interfaces: {}", strerror(err));
            return links;
        }

        // One next hop of a default route in the main table.
        struct default_hop
        {
            uint32_t metric;
            int ifindex;
            std::optional<std::array<uint8_t, 16>> gateway;  // first 4 bytes for IPv4
        };

        static std::vector<default_hop> dump_default_hops(int af)
        {
            std::vector<default_hop> hops;
            struct
            {
                nlmsghdr header;
                rtmsg content;
            } req{};
            req.header.nlmsg_len = NLMSG_LENGTH(sizeof req.content);
            req.header.nlmsg_type = RTM_GETROUTE;
            req.content.rtm_family = static_cast<unsigned char>(af);
            const size_t alen = af == AF_INET ? 4 : 16;
            int err = nl_dump(req, [&](nlmsghdr* h) {
                if (h->nlmsg_type != RTM_NEWROUTE)
                    return;
                auto* rt = static_cast<rtmsg*>(NLMSG_DATA(h));
                if (rt->rtm_family != af or rt->rtm_dst_len != 0 or rt->rtm_type != RTN_UNICAST
                    or rt->rtm_protocol == RTPROT_SROUTER or (rt->rtm_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN)))
                    return;
                uint32_t table = rt->rtm_table, metric = 0;
                int oif = 0;
                std::optional<std::array<uint8_t, 16>> gw;
                auto read_gw = [alen](const rtattr* a) {
                    std::array<uint8_t, 16> g{};
                    if (RTA_PAYLOAD(a) >= alen)
                        std::memcpy(g.data(), RTA_DATA(a), alen);
                    return g;
                };
                const rtattr* multipath = nullptr;
                int len = RTM_PAYLOAD(h);
                for (auto* a = RTM_RTA(rt); RTA_OK(a, len); a = RTA_NEXT(a, len))
                {
                    switch (a->rta_type)
                    {
                        case RTA_TABLE:
                            table = *static_cast<const uint32_t*>(RTA_DATA(a));
                            break;
                        case RTA_PRIORITY:
                            metric = *static_cast<const uint32_t*>(RTA_DATA(a));
                            break;
                        case RTA_OIF:
                            oif = *static_cast<const int*>(RTA_DATA(a));
                            break;
                        case RTA_GATEWAY:
                            gw = read_gw(a);
                            break;
                        case RTA_MULTIPATH:
                            multipath = a;
                            break;
                    }
                }
                if (table != RT_TABLE_MAIN)
                    return;
                if (not multipath)
                {
                    if (oif)
                        hops.push_back({metric, oif, gw});
                    return;
                }
                // ECMP: each next hop is an rtnexthop followed by its own attributes.
                int mlen = RTA_PAYLOAD(multipath);
                for (auto* nh = static_cast<const rtnexthop*>(RTA_DATA(multipath));
                     mlen >= static_cast<int>(sizeof(rtnexthop)) and nh->rtnh_len >= sizeof(rtnexthop)
                     and static_cast<int>(nh->rtnh_len) <= mlen;
                     mlen -= RTNH_ALIGN(nh->rtnh_len), nh = RTNH_NEXT(nh))
                {
                    if (nh->rtnh_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN))
                        continue;
                    std::optional<std::array<uint8_t, 16>> nhgw;
                    int alen_left = nh->rtnh_len - sizeof(rtnexthop);
                    for (auto* a = RTNH_DATA(nh); RTA_OK(a, alen_left); a = RTA_NEXT(a, alen_left))
                        if (a->rta_type == RTA_GATEWAY)
                            nhgw = read_gw(a);
                    hops.push_back({metric, nh->rtnh_ifindex, nhgw});
                }
            });
            if (err)
                log::warning(logcat, "Failed to list IPv{} routes: {}", af == AF_INET ? 4 : 6, strerror(err));
            return hops;
        }

        // One of the interface's own addresses in the given family, preferring a global one, to
        // stand in for the gateway of a gateway-less default route.
        static std::optional<std::array<uint8_t, 16>> own_address(const std::string& ifname, int af)
        {
            ifaddrs* head;
            if (getifaddrs(&head) != 0)
                return std::nullopt;
            call_on_destroy freer{[head] { freeifaddrs(head); }};
            std::optional<std::array<uint8_t, 16>> found;
            for (auto* ia = head; ia; ia = ia->ifa_next)
            {
                if (not ia->ifa_addr or ia->ifa_addr->sa_family != af or ifname != ia->ifa_name)
                    continue;
                std::array<uint8_t, 16> a{};
                if (af == AF_INET)
                {
                    std::memcpy(a.data(), &reinterpret_cast<sockaddr_in*>(ia->ifa_addr)->sin_addr, 4);
                    return a;
                }
                const auto& in6 = reinterpret_cast<sockaddr_in6*>(ia->ifa_addr)->sin6_addr;
                std::memcpy(a.data(), &in6, 16);
                if (not IN6_IS_ADDR_LINKLOCAL(&in6))
                    return a;
                if (not found)
                    found = a;
            }
            return found;
        }

      public:
        LinuxRouteManager() : fd{socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE)}
        {
            if (fd == -1)
                throw std::runtime_error{"netlink failed: {}"_format(strerror(errno))};
            // The kernel always answers a request with NLM_F_ACK, but don't let a lost reply hang us.
            timeval tv{.tv_sec = 2, .tv_usec = 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }

        ~LinuxRouteManager() override { close(fd); }

        void add_route(ipv4 ip, ipv4 gateway) override
        {
            route_via_gateway(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, ip, gateway);
        }
        void add_route(ipv6 ip, ipv6 gateway) override
        {
            route_via_gateway(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, ip, gateway);
        }

        void delete_route(ipv4 ip, ipv4 gateway) override { route_via_gateway(RTM_DELROUTE, 0, ip, gateway); }
        void delete_route(ipv6 ip, ipv6 gateway) override { route_via_gateway(RTM_DELROUTE, 0, ip, gateway); }

        void add_default_route_via_interface(NetworkInterface& vpn) override
        {
            route_all_via_interface(vpn, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL);
        }

        void delete_default_route_via_interface(NetworkInterface& vpn) override
        {
            route_all_via_interface(vpn, RTM_DELROUTE, 0);
        }

        void add_route_via_interface(NetworkInterface& vpn, ipv4_range range) override
        {
            route_range_via_interface(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, vpn, range);
        }
        void add_route_via_interface(NetworkInterface& vpn, ipv6_range range) override
        {
            route_range_via_interface(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, vpn, range);
        }

        void delete_route_via_interface(NetworkInterface& vpn, ipv4_range range) override
        {
            route_range_via_interface(RTM_DELROUTE, 0, vpn, range);
        }

        void delete_route_via_interface(NetworkInterface& vpn, ipv6_range range) override
        {
            route_range_via_interface(RTM_DELROUTE, 0, vpn, range);
        }

        // Returns the default gateways that can carry traffic now, IPv4 then IPv6, each lowest
        // metric first (ties go to the lower interface index).  A default route only counts if
        // its interface is up with a carrier and isn't the TUN, another VPN or overlay tunnel, or
        // loopback; PPP and cellular links do count, with or without a gateway.  Routes the kernel
        // marks dead or link-down, and our own, are skipped.
        std::vector<quic::Address> get_non_interface_gateways(NetworkInterface& vpn) override
        {
            const auto& ifname = vpn.interface_info().ifname;
            const auto links = dump_links();

            std::vector<quic::Address> gateways{};
            gw_info4.clear();
            gw_info6.clear();
            for (int af : {AF_INET, AF_INET6})
            {
                auto hops = dump_default_hops(af);
                std::ranges::stable_sort(hops, {}, [](const auto& h) { return std::pair{h.metric, h.ifindex}; });
                for (const auto& hop : hops)
                {
                    auto it = links.find(hop.ifindex);
                    if (it == links.end() or not it->second.usable or it->second.name == ifname)
                        continue;
                    bool device_only = not hop.gateway;
                    auto addr = device_only ? own_address(it->second.name, af) : hop.gateway;
                    if (not addr)
                        continue;
                    if (af == AF_INET)
                    {
                        in_addr a{};
                        std::memcpy(&a, addr->data(), 4);
                        ipv4 gw{a};
                        if (gw == ipv4{} or not gw_info4.emplace(gw, gw_info{hop.ifindex, device_only}).second)
                            continue;
                        gateways.emplace_back(gw, 0);
                    }
                    else
                    {
                        ipv6 gw{std::span<const uint8_t, 16>{addr->data(), 16}};
                        if (gw == ipv6{} or not gw_info6.emplace(gw, gw_info{hop.ifindex, device_only}).second)
                            continue;
                        gateways.emplace_back(gw, 0);
                    }
                    log::debug(
                        logcat,
                        "Default route candidate: {} metric {}",
                        device_only ? "dev {}"_format(it->second.name)
                                    : "via {} dev {}"_format(gateways.back().host(), it->second.name),
                        hop.metric);
                }
            }
            return gateways;
        }

        void add_blackhole() override
        {
            make_blackhole(RTM_NEWROUTE, NLM_F_CREATE, AF_INET);
            make_blackhole(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, AF_INET6);
        }

        void delete_blackhole() override
        {
            make_blackhole(RTM_DELROUTE, 0, AF_INET);
            make_blackhole(RTM_DELROUTE, 0, AF_INET6);
        }

        // Removes every main-table route carrying our protocol number: the blackholes and
        // first-hop host routes a run that was killed left behind.  (Routes via its TUN went
        // away with the device.)  Another instance running with route poking on uses the same
        // protocol number, so its routes would go too; that setup isn't supported.
        void delete_stale_routes() override
        {
            std::vector<std::vector<char>> stale;
            for (int af : {AF_INET, AF_INET6})
            {
                struct
                {
                    nlmsghdr header;
                    rtmsg content;
                } req{};
                req.header.nlmsg_len = NLMSG_LENGTH(sizeof req.content);
                req.header.nlmsg_type = RTM_GETROUTE;
                req.content.rtm_family = static_cast<unsigned char>(af);
                int err = nl_dump(req, [&stale](nlmsghdr* h) {
                    auto* rt = static_cast<rtmsg*>(NLMSG_DATA(h));
                    if (h->nlmsg_type == RTM_NEWROUTE and rt->rtm_protocol == RTPROT_SROUTER
                        and rt->rtm_table == RT_TABLE_MAIN)
                        stale.emplace_back(reinterpret_cast<char*>(h), reinterpret_cast<char*>(h) + h->nlmsg_len);
                });
                if (err)
                    log::warning(logcat, "Failed to list IPv{} routes: {}", af == AF_INET ? 4 : 6, strerror(err));
            }

            int removed = 0;
            for (auto& msg : stale)
            {
                NLRequest req{};
                if (msg.size() > sizeof(req))
                    continue;
                std::memcpy(&req, msg.data(), msg.size());
                req.header.nlmsg_type = RTM_DELROUTE;
                req.header.nlmsg_flags = NLM_F_REQUEST;
                req.header.nlmsg_pid = 0;
                if (int err = submit(req); not benign(RTM_DELROUTE, err))
                    log::warning(logcat, "Failed to remove a route left by an earlier run: {}", strerror(err));
                else
                    ++removed;
            }
            if (removed)
                log::info(logcat, "Removed {} route(s) left behind by an earlier run", removed);
        }
    };

    class LinuxPlatform : public Platform
    {
        LinuxRouteManager _routeManager{};

      public:
        std::shared_ptr<NetworkInterface> obtain_interface(InterfaceInfo info, Router*) override
        {
            return std::make_shared<LinuxInterface>(std::move(info));
        };

        AbstractRouteManager& RouteManager() override { return _routeManager; }
    };

}  // namespace srouter::vpn
