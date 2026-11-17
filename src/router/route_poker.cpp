#include "route_poker.hpp"

#include "handlers/tun.hpp"
#include "link/link_manager.hpp"
#include "router.hpp"

namespace srouter
{
    static auto logcat = log::Cat("route_poker");

    RoutePoker::RoutePoker(Router& r, handlers::TunEndpoint& tun) : _router{r}, _tun{tun}
    {
        _enabled = r.config().network.enable_route_poker;
        if (_enabled)
            log::info(logcat, "Route poker enabled by [network] auto-routing");
    }

    template <IP46 IP>
    void RoutePoker::add_route(const IP& ip)
    {
        // Always record the hop so pre-put_up poke_first_hop is not dropped on the floor.
        // When !_up we only store (empty gateway); put_up flushes via refresh/enable before
        // installing default-via-TUN.
        auto& poked_rs = poked_routes<IP>();
        auto [it, new_route] = poked_rs.emplace(ip, IP{});
        auto& gw = it->second;

        if (not _up)
        {
            if (new_route)
                log::debug(logcat, "RoutePoker: recorded first-hop {} pending put_up", ip);
            return;
        }

        auto& current_gw = current_gateway<IP>();
        if (!current_gw)
        {
            gw = IP{};
            return;
        }

        // Already routed via the current gateway: leave it alone.  Deleting and re-adding the
        // host route would, for a moment, send this first hop's traffic down the default route
        // (i.e. into the TUN once it is up) and break the live connection.
        if (!new_route and gw == *current_gw)
            return;

        // remove existing mapping (via an old gateway) as needed
        if (!new_route and gw != IP{})
            disable_route(ip, gw);
        gw = IP{};

        // Only count the hop as pinned once the kernel has taken the route.  On failure the
        // gateway stays empty, so the next attempt tries again instead of skipping it.
        try
        {
            enable_route(ip, *current_gw);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Could not pin first hop {}: {}", ip, e.what());
            return;
        }
        gw = *current_gw;
        log::info(logcat, "Added route to {} via {}", ip, gw);
    }
    template void RoutePoker::add_route(const ipv4& ip);
    template void RoutePoker::add_route(const ipv6& ip);

    template <IP46 IP>
    void RoutePoker::add_first_hop(const IP& ip)
    {
        // A dial while we're up is often a reconnect after a network change, so check the gateway
        // first: update() re-pins every recorded first hop if it moved.
        if (_up)
            update();
        add_route(ip);
    }
    template void RoutePoker::add_first_hop(const ipv4& ip);
    template void RoutePoker::add_first_hop(const ipv6& ip);

    template <IP46 IP>
    void RoutePoker::disable_route(const IP& ip, const IP& gateway)
    {
        if (_enabled and ip != IP{})
        {
            log::info(logcat, "Deleting route to {} via {}", ip, gateway);
            _router.vpn_platform()->RouteManager().delete_route(ip, gateway);
        }
    }
    template void RoutePoker::disable_route(const ipv4&, const ipv4&);
    template void RoutePoker::disable_route(const ipv6&, const ipv6&);

    template <IP46 IP>
    void RoutePoker::enable_route(const IP& ip, const IP& gateway)
    {
        if (_enabled and ip != IP{})
            _router.vpn_platform()->RouteManager().add_route(ip, gateway);
    }
    template void RoutePoker::enable_route(const ipv4&, const ipv4&);
    template void RoutePoker::enable_route(const ipv6&, const ipv6&);

    void RoutePoker::delete_all_routes()
    {
        for (auto it = poked_routes4.begin(); it != poked_routes4.end();)
            it = delete_route(it);
        for (auto it = poked_routes6.begin(); it != poked_routes6.end();)
            it = delete_route(it);
    }

    void RoutePoker::start()
    {
        if (not _enabled)
        {
            log::info(logcat, "Route poker is NOT enabled for this Session Router instance!");
            return;
        }

        // A run that was killed with routes up leaves its blackhole and first-hop routes behind;
        // the blackhole alone would keep the machine offline.
        if (const auto& platform = _router.vpn_platform())
        {
            log::debug(logcat, "Removing any routes left by an earlier run");
            platform->RouteManager().delete_stale_routes();
        }

        // Discover gateway once at start; put_up() re-discovers.  Avoid 100ms hammer.
        update();
    }

    void RoutePoker::disable_all_routes()
    {
        for (const auto& [ip, gateway] : poked_routes4)
            disable_route(ip, gateway);
        for (const auto& [ip, gateway] : poked_routes6)
            disable_route(ip, gateway);
    }

    void RoutePoker::refresh_all_routes()
    {
        for (const auto& [ip, gw] : poked_routes4)
            add_route(ip);
        for (const auto& [ip, gw] : poked_routes6)
            add_route(ip);
    }

    RoutePoker::~RoutePoker()
    {
        if (not _router.vpn_platform())
            return;

        // Routes via the TUN go away with the interface itself.
        delete_all_routes();
        if (_blackhole_up)
            _router.vpn_platform()->RouteManager().delete_blackhole();
    }

    void RoutePoker::update()
    {
        auto platform = _router.vpn_platform();
        if (not platform)
            return;
        auto* vpn = _tun.get_vpn_interface();
        if (vpn == nullptr)
            return;

        auto gateways = platform->RouteManager().get_non_interface_gateways(*vpn);

        std::optional<ipv4> next4;
        std::optional<ipv6> next6;
        for (auto& g : gateways)
        {
            if (g.is_ipv4() and not next4)
            {
                if (auto v4 = g.to_ipv4(); v4 != ipv4{})
                    next4 = v4;
            }
            else if (g.is_ipv6() and not next6)
            {
                if (auto v6 = g.to_ipv6(); v6 != ipv6{})
                    next6 = v6;
            }
        }

        bool changed = false;
        if (next4 != current_gateway4)
        {
            if (next4 and current_gateway4)
                log::info(logcat, "IPv4 default gateway changed from {} to {}", *current_gateway4, *next4);
            else if (current_gateway4)
                log::warning(logcat, "IPv4 default gateway {} has gone away", *current_gateway4);
            else if (next4)
                log::info(logcat, "IPv4 default gateway found at {}", *next4);
            current_gateway4 = next4;
            changed = true;
        }
        if (next6 != current_gateway6)
        {
            if (next6 and current_gateway6)
                log::info(logcat, "IPv6 default gateway changed from {} to {}", *current_gateway6, *next6);
            else if (current_gateway6)
                log::warning(logcat, "IPv6 default gateway {} has gone away", *current_gateway6);
            else if (next6)
                log::info(logcat, "IPv6 default gateway found at {}", *next6);
            current_gateway6 = next6;
            changed = true;
        }

        if (changed)
            refresh_all_routes();
    }

    bool RoutePoker::put_up()
    {
        if (_up)
            return true;

        update();

        if (not _router.vpn_platform() or not _tun.get_vpn_interface())
        {
            log::warning(logcat, "Route poker: no VPN interface; not installing exit routes");
            _down_reason = "no vpn interface";
            return false;
        }

        if (not current_gateway4 and not current_gateway6)
        {
            log::warning(logcat, "Route poker: no default gateway found; not installing exit routes");
            _down_reason = "no default gateway";
            return false;
        }

        // Pin every first hop (recorded before we came up, established, and still dialing) via the
        // real gateway before anything is routed into the TUN, or the edge connections that carry
        // the tunnel would end up inside it.
        _up = true;
        refresh_all_routes();

        auto poke_remote = [this](const quic::Address& remote) {
            if (remote.is_any_addr())
                return;
            if (remote.is_ipv4())
                add_route(remote.to_ipv4());
            else
                add_route(remote.to_ipv6());
        };

        // Every current edge connection has to be pinned before anything goes via the TUN: one
        // that isn't would have its traffic routed into the tunnel it carries.
        size_t pinned = 0, unpinned = 0;
        auto check_remote = [&](const quic::Address& remote) {
            if (remote.is_any_addr())
                return;
            bool ok = false;
            if (remote.is_ipv4())
            {
                auto it = poked_routes4.find(remote.to_ipv4());
                ok = it != poked_routes4.end() and it->second != ipv4{};
            }
            else
            {
                auto it = poked_routes6.find(remote.to_ipv6());
                ok = it != poked_routes6.end() and it->second != ipv6{};
            }
            if (ok)
                ++pinned;
            else
            {
                ++unpinned;
                log::warning(logcat, "Route poker: first hop {} is not pinned", remote);
            }
        };

        auto& endpoint = _router.link_manager().endpoint;
        for (const auto& remote : endpoint.first_hop_addrs())
        {
            poke_remote(remote);
            check_remote(remote);
        }

        if (pinned == 0 or unpinned > 0)
        {
            log::warning(
                logcat,
                "Route poker: {} of {} first-hop route(s) could not be pinned; not installing exit routes",
                unpinned,
                pinned + unpinned);
            _up = false;
            _down_reason = "first hop not pinned";
            return false;
        }

        _down_reason = nullptr;
        log::info(logcat, "Route poker up; pinned {} first-hop route(s)", pinned);
        return true;
    }

    void RoutePoker::set_default_route(bool up)
    {
        auto& route = _router.vpn_platform()->RouteManager();
        if (up and not _default_up)
        {
            // Set the flags first: if an install throws partway, put_down() still removes the
            // blackhole and whatever part of the default route did go in (deletes of routes that
            // were never added are ignored).
            if (_router.config().network.blackhole_routes and not _blackhole_up)
            {
                _blackhole_up = true;
                route.add_blackhole();
            }
            _default_up = true;
            _tun.add_default_route();
            log::info(logcat, "Default route via TUN installed");
        }
        else if (not up and _default_up)
        {
            // The default route goes before anything else so that nothing falls into the TUN that
            // shouldn't while the rest comes down.
            _default_up = false;
            _tun.delete_default_route();
            if (_blackhole_up)
            {
                route.delete_blackhole();
                _blackhole_up = false;
            }
            log::info(logcat, "Default route via TUN removed");
        }
    }

    void RoutePoker::update_exit_routes()
    {
        assert(_router.loop().inside());
        if (not _enabled)
            return;

        bool full = false;
        std::set<ipv4_range> want4;
        std::set<ipv6_range> want6;
        for (const auto& [addr, ranges] : _router.config().exit.ranges)
        {
            for (const auto& r : ranges)
            {
                if (const auto* r4 = std::get_if<ipv4_range>(&r))
                {
                    if (r4->mask == 0)
                        full = true;
                    else
                        want4.insert(*r4);
                }
                else if (const auto& r6 = std::get<ipv6_range>(r); r6.mask == 0)
                    full = true;
                else
                    want6.insert(r6);
            }
        }

        if (not full and want4.empty() and want6.empty())
        {
            put_down();
            return;
        }

        if (not put_up())
        {
            schedule_retry();
            return;
        }

        auto& route = _router.vpn_platform()->RouteManager();
        auto& vpn = *_tun.get_vpn_interface();

        try
        {
            if (not full)
                set_default_route(false);

            auto sync = [&](auto& have, const auto& want) {
                for (auto it = have.begin(); it != have.end();)
                {
                    if (want.contains(*it))
                        ++it;
                    else
                    {
                        route.delete_route_via_interface(vpn, *it);
                        log::info(logcat, "Removed route to {} via TUN", *it);
                        it = have.erase(it);
                    }
                }
                for (const auto& r : want)
                {
                    if (have.contains(r))
                        continue;
                    route.add_route_via_interface(vpn, r);
                    have.insert(r);
                    log::info(logcat, "Added route to {} via TUN", r);
                }
            };
            sync(_tun_routes4, want4);
            sync(_tun_routes6, want6);

            if (full)
                set_default_route(true);
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Route poker: failed to install exit routes ({}); taking them down", e.what());
            _down_reason = "route refused";
            put_down();
            schedule_retry();
        }
    }

    void RoutePoker::schedule_retry()
    {
        if (_retry_pending)
            return;
        _retry_pending = true;
        log::info(logcat, "Route poker: retrying the exit routes in {}s", RETRY_INTERVAL.count());
        _router.loop().call_later(RETRY_INTERVAL, [this, alive = std::weak_ptr{_alive}] {
            if (alive.expired())
                return;
            _retry_pending = false;
            update_exit_routes();
        });
    }

    void RoutePoker::edges_lost()
    {
        if (not _up)
            return;
        // With blackhole-routes on (the default) the routes stay in place while there are no edge
        // connections, so traffic is dropped instead of leaking out of the real gateway until the
        // edges come back.  New first hops are pinned before they are dialled.  They only come
        // down on unmap or shutdown.
        if (_router.config().network.blackhole_routes)
        {
            log::info(logcat, "Route poker: no edge connections; keeping the exit routes until they reconnect");
            return;
        }
        put_down();
    }

    void RoutePoker::put_down()
    {
        if (not _up)
            return;
        _up = false;

        if (_enabled and _router.vpn_platform())
        {
            set_default_route(false);

            if (auto* vpn = _tun.get_vpn_interface())
            {
                auto& route = _router.vpn_platform()->RouteManager();
                for (const auto& r : _tun_routes4)
                    route.delete_route_via_interface(*vpn, r);
                for (const auto& r : _tun_routes6)
                    route.delete_route_via_interface(*vpn, r);
            }
            _tun_routes4.clear();
            _tun_routes6.clear();
        }

        delete_all_routes();
        log::info(logcat, "Route poker down");
    }

    std::string_view RoutePoker::routes_reason() const
    {
        if (_up)
            return {};
        if (not _enabled)
            return "auto-routing disabled";
        return _down_reason ? std::string_view{_down_reason} : std::string_view{};
    }

}  // namespace srouter
