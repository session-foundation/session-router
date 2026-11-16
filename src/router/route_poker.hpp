#pragma once

#include "address/types.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>

namespace srouter
{
    class Router;

    namespace handlers
    {
        class TunEndpoint;
    }

    template <typename IP>
    concept IP46 = std::same_as<IP, ipv4> || std::same_as<IP, ipv6>;

    class RoutePoker
    {
      public:
        RoutePoker(Router& r, handlers::TunEndpoint& tun);
        RoutePoker(const RoutePoker&) = delete;
        RoutePoker(RoutePoker&&) = delete;
        RoutePoker& operator=(const RoutePoker&) = delete;
        RoutePoker& operator=(RoutePoker&&) = delete;

        template <IP46 IP>
        void add_route(const IP& ip);

        /// Pins a first hop being dialled, re-checking the default gateway first when up.
        template <IP46 IP>
        void add_first_hop(const IP& ip);

        template <IP46 IP>
        void delete_route(const IP& ip)
        {
            auto& pr = poked_routes<IP>();
            if (auto it = pr.find(ip); it != pr.end())
                delete_route(it);
        }

        void start();

        ~RoutePoker();

        /// Brings the OS routes in line with the current exit mappings.  With no mappings everything
        /// is taken down.  Otherwise first hops are pinned via the real gateway, each mapped range
        /// is routed via the TUN, and a /0 mapping also installs the default route via the TUN
        /// (plus the blackhole, if enabled).  Must be called on the router loop.
        void update_exit_routes();

        /// Removes every route this poker installed.
        void put_down();

        /// Called when the last edge connection goes.  Keeps the routes (fail closed) when
        /// blackhole-routes is on, otherwise takes them down until the edges come back.
        void edges_lost();

        /// set dns resolver
        /// pass in if we are using exit node mode right now  as a bool
        // void set_dns_mode(bool using_exit_mode) const;
        // NOTE: without set_dns_mode the system resolver is left alone.  An on-link LAN resolver
        // is still reached directly (its subnet route beats the routes via the TUN); any other
        // resolver goes through the exit, which can't reach a private one.

        bool enabled() const { return _enabled; }
        bool is_up() const { return _up; }

      private:
        // Discovers the gateways and pins first-hop host routes; returns false (and stays down) if
        // there is no gateway or nothing to pin.
        bool put_up();

        void update();

        void set_default_route(bool up);

        // Tries update_exit_routes() again later, after routes couldn't be put up.
        void schedule_retry();
        static constexpr std::chrono::seconds RETRY_INTERVAL{5};
        bool _retry_pending{false};
        std::shared_ptr<bool> _alive = std::make_shared<bool>(true);

        void delete_all_routes();

        void disable_all_routes();

        void refresh_all_routes();

        template <IP46 IP>
        void enable_route(const IP& ip, const IP& gateway);

        template <IP46 IP>
        void disable_route(const IP& ip, const IP& gateway);

        std::unordered_map<ipv4, ipv4> poked_routes4;
        std::unordered_map<ipv6, ipv6> poked_routes6;
        std::optional<ipv4> current_gateway4;
        std::optional<ipv6> current_gateway6;

        template <IP46 IP>
        std::unordered_map<IP, IP>& poked_routes()
        {
            if constexpr (std::same_as<IP, ipv4>)
                return poked_routes4;
            else
                return poked_routes6;
        }
        template <IP46 IP>
        std::optional<IP>& current_gateway()
        {
            if constexpr (std::same_as<IP, ipv4>)
                return current_gateway4;
            else
                return current_gateway6;
        }

        template <IP46 IP>
        using poked_iterator = std::unordered_map<IP, IP>::iterator;

        template <typename It>
            requires std::same_as<It, poked_iterator<ipv4>> || std::same_as<It, poked_iterator<ipv6>>
        auto delete_route(It it)
        {
            disable_route(it->first, it->second);
            using IP = std::conditional_t<std::same_as<It, poked_iterator<ipv4>>, ipv4, ipv6>;
            return poked_routes<IP>().erase(it);
        }

        Router& _router;
        handlers::TunEndpoint& _tun;
        bool _up{false};
        bool _enabled{false};
        bool _default_up{false};
        bool _blackhole_up{false};
        std::set<ipv4_range> _tun_routes4;
        std::set<ipv6_range> _tun_routes6;
    };

    extern template void RoutePoker::add_route(const ipv4&);
    extern template void RoutePoker::add_route(const ipv6&);
    extern template void RoutePoker::add_first_hop(const ipv4&);
    extern template void RoutePoker::add_first_hop(const ipv6&);
    extern template void RoutePoker::enable_route(const ipv4& ip, const ipv4& gateway);
    extern template void RoutePoker::enable_route(const ipv6& ip, const ipv6& gateway);
    extern template void RoutePoker::disable_route(const ipv4& ip, const ipv4& gateway);
    extern template void RoutePoker::disable_route(const ipv6& ip, const ipv6& gateway);

}  // namespace srouter
