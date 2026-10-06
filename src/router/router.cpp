#include "router.hpp"

#include "config/config.hpp"
#include "constants/platform.hpp"
#include "constants/proto.hpp"
#include "constants/version.hpp"
#include "contact/contactdb.hpp"
#include "crypto/crypto.hpp"
#include "link/link_manager.hpp"
#include "nodedb.hpp"
#include "util/formattable.hpp"
#include "util/logging.hpp"
#include "util/random.hpp"
#include "util/service_manager.hpp"
#include "util/time.hpp"
#include "util/try_calling.hpp"

#include <nlohmann/json.hpp>
#include <oxen/log.hpp>

#include <chrono>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <utility>

#if defined(ANDROID) || defined(IOS)
#include <unistd.h>
#endif

#if defined(WITH_SYSTEMD)
#include <systemd/sd-daemon.h>
#endif

namespace srouter
{
    static auto logcat = log::Cat("router");

    Router::Router(
        Config conf, std::shared_ptr<quic::Loop> loop, std::shared_ptr<vpn::Platform> vpnPlatform, std::promise<void> p)
        : _config{std::move(conf)},
          _loop{std::move(loop)},
          _jq{std::make_unique<quic::JobQueue>(*_loop)},
          _vpn{std::move(vpnPlatform)},
          _close_promise{std::move(p)},
          _contact_db{std::make_unique<ContactDB>(*this)},
          _last_tick{}
    {
        // Full builds install the rpc backend (srouter::full::initialize); in embedded/core-only
        // builds rpc_backend is null and these stay null (the relay/rpc paths never run).
        if (rpc_backend)
        {
            _omq = rpc_backend->make_omq();
            if (is_service_node)
                _router_testing = rpc_backend->make_reachability(*this);
        }

        init_logging();

        _jq->call_get([this] {
            log::debug(logcat, "Inside router loop, initializing router");
            configure();
            start();
        });
    }

    // Out-of-line because some of the unique_ptrs are for forward-declared types in router.hpp which
    // aren't available for destruction, but are available here.
    //
    // Stopping the queues has to happen here, before any member is destroyed: they own every timer
    // and pending job in the router, all of which reference members that are about to go away.  (The
    // queues themselves are destroyed far too late for this -- they are declared near the top of
    // Router so that components can use them during construction, which makes them almost the last
    // things to die.)
    Router::~Router()
    {
        _jq->stop();
        disk_jq.stop();
    }

    void Router::start_timers()
    {
        if (_tun)
            _tun->start_poller();

        if (!embedded())
            _service_stat_timer = _jq->add_timer(SERVICE_MANAGER_REPORT_INTERVAL, [this]() {
                sys::service_manager->report_periodic_stats(status_line());
            });

        _node_db->start();
        _contact_db->start_timers();
        _link_endpoint->start_timers();

        if (is_service_node)
        {
            _oxend->start_pings();

            auto delay = uniform_duration_distribution{10s, 15s}(srouter::csrng);
            if (auto* rc = _node_db->get_rc(id());
                rc && rc->age(srouter::time_now_ms()) < RelayContact::MIN_GOSSIP_RC_AGE)
            {
                // If we already have our own RC, and it's very new then most likely the network
                // won't accept it right now anyway because we will have just sent it and restarted,
                // so delay by additional minimum acceptable gossip age before first sending it out.
                delay += RelayContact::MIN_GOSSIP_RC_AGE;
            }
            log::debug(logcat, "Delaying initial RC broadcast for {}", delay);
            _jq->call_later(delay, [this] {
                regenerate_rc();
                log::debug(logcat, "Starting RC regen timer");
                _gossip_timer = _jq->add_timer(RC_UPDATE_INTERVAL, [this] { regenerate_rc(); });
            });

            if (not _config.oxend.disable_testing)
                _router_testing->start();
        }
        else
        {
            // Resolve needed ONS values now that we have the necessary things prefigured
            _session_endpoint->resolve_sns_mappings();
        }
    }

    bool Router::is_fully_meshed() const { return link_endpoint().num_relay_conns() >= _node_db->num_rcs(); }

    void Router::fetch_snode_keys()
    {
        assert(is_service_node);

        our_rc_file = _config.router.data_dir / our_rc_filename;

#if defined(ANDROID) || defined(IOS)
        log::critical(logcat, "running a service node on mobile devices is not possible.");
        throw std::runtime_error{"Invalid SNode configuration"};
#elif defined(_WIN32)
        log::critical(logcat, "running a service node on windows is not possible.");
        throw std::runtime_error{"Invalid SNode configuration"};
#endif
        constexpr int maxTries = 5;
        int numTries = 0;
        while (numTries < maxTries)
        {
            numTries++;
            try
            {
                key_manager.update_idkey(_oxend->obtain_identity_key());
                log::info(log_global, "Obtained service node identity from oxend: {}", key_manager.router_id());
                break;
            }
            catch (const std::exception& e)
            {
                log::warning(
                    log_global, "Failed attempt {} of {} to get oxend id keys: ", numTries, maxTries, e.what());

                if (numTries == maxTries)
                    throw;
            }
        }
    }

    void Router::init_logging()
    {
        if (_config.logging.type)
        {
            auto log_type = *_config.logging.type;

            // Backwards compat: before 0.9.10 we used `type=file` with `file=|-|stdout` for print mode
            if (log_type == log::Type::File
                && (_config.logging.file == "stdout" || _config.logging.file == "-" || _config.logging.file.empty()))
                log_type = log::Type::Print;

#ifndef NDEBUG
            std::string debug_pattern =
                log_type == log::Type::Print ? log::DEFAULT_PATTERN_COLOR : log::DEFAULT_PATTERN_MONO;
            // In a debug build replace YYYY-MM-DD with "t=THREADID"
            if (auto pos = debug_pattern.find("%Y-%m-%d"); pos != std::string::npos)
                debug_pattern = debug_pattern.substr(0, pos) + "t=%t" + debug_pattern.substr(pos + 8);
            else
                debug_pattern = "[t=%t] " + debug_pattern;
#endif

            log::clear_sinks();
            log::add_sink(
                log_type,
                log_type == log::Type::System ? "session-router" : _config.logging.file
#ifndef NDEBUG
                ,
                debug_pattern
#endif
            );
        }

        log::extract_categories(_config.logging.levels).apply([](log::Level global_level) {
            // Override the global category to always print at info level, even when the
            // overall/default level is set higher.
            if (global_level > log::Level::info)
                log::set_level(log_global, log::Level::info);
        });

        // re-add rpc log sink if rpc enabled, else free it
        if (_config.api.enable_rpc_server and srouter::logRingBuffer)
            log::add_sink(srouter::logRingBuffer, srouter::log::DEFAULT_PATTERN_MONO);
        else
            srouter::logRingBuffer.reset();
    }

    void Router::process_config()
    {
        if (is_service_node && embedded())
            throw std::runtime_error{"Invalid config: service node and embedded modes are incompatible!"};

        if (is_service_node)
        {
            auto paddr = _config.router.public_addr;

            // Treat 0.0.0.0:0 as not specified:
            if (_config.links.listen_addr && _config.links.listen_addr->is_any_addr()
                && _config.links.listen_addr->is_any_port())
                _config.links.listen_addr.reset();

            // If our given public address has a port of 0 then set port to the listen port (if
            // one was explicitly given) or otherwise the default relay port.
            if (paddr)
            {
                if (paddr->is_any_port() && _config.links.listen_addr)
                    paddr->set_port(_config.links.listen_addr->port());
                if (paddr->is_any_port())
                    paddr->set_port(DEFAULT_RELAY_PORT);

                _public_address = paddr;
                if (!_public_address->is_public())
                    throw std::runtime_error{"Invalid public-ip: given IP address is not a public IP address"};
            }

            bool auto_detect = false;
            uint16_t auto_port = DEFAULT_RELAY_PORT;

            if (!_config.links.listen_addr)
            {
                if (_public_address)
                {
                    // No listen address, but a public ip/port were given
                    // if that public addr is on an interface on the system, use it
                    // if not, and any other public addr is on an interface, error
                    // else listen on the `any` address
                    if (_public_address->is_ipv4() && net()->has_interface_address(_public_address->to_ipv4()))
                        _listen_address = *_public_address;
                    else if (_public_address->is_ipv6() && net()->has_interface_address(_public_address->to_ipv6()))
                        _listen_address = *_public_address;
                    else if (net()->get_best_public_address(true, _public_address->port()))
                        throw std::runtime_error{
                            "Invalid public/listen address combination.  Public address not on the system was "
                            "specified, listen address was not specified, and there is a public address on the system. "
                            " Check that [router]:public-ip is set correctly."};
                    else
                        _listen_address = quic::Address{"0.0.0.0", _public_address->port()};
                }
                else
                    auto_detect = true;
            }
            else if (_config.links.listen_addr->is_any_addr())
            {
                assert(!_config.links.listen_addr->is_any_port());  // Should be assured from above
                // port given but not IP: if we have a public ip then use that, else go search
                if (paddr)
                    _listen_address = quic::Address{paddr->host(), _config.links.listen_addr->port()};
                else
                {
                    auto_detect = true;
                    auto_port = _config.links.listen_addr->port();
                }
            }
            else if (_config.links.listen_addr->is_any_port())
            {
                // IP given but not port.  If we have a public port use that, otherwise use the
                // default.
                _listen_address = *_config.links.listen_addr;
                _listen_address.set_port(paddr ? paddr->port() : DEFAULT_RELAY_PORT);
            }
            else
            {
                assert(_config.links.listen_addr->is_addressable());
                _listen_address = *_config.links.listen_addr;
            }

            if (auto_detect)
            {
                assert(net());
                if (auto maybe_addr = net()->get_best_public_address(true, auto_port))
                    _public_address = _listen_address = std::move(*maybe_addr);
                else
                    throw std::runtime_error{
                        "Unable to determine a public IP on this system; you likely need to set "
                        "[router]:public-ip/public-port config settings"};
            }

            if (!_public_address)
            {
                if (_listen_address.is_public())
                    _public_address = _listen_address;
                else
                    throw std::runtime_error{"When listening on a non-public IP, public-ip must be specified"};
            }

            if (_listen_address == *_public_address)
                log::info(logcat, "Using {} for Session Router communications", _listen_address);
            else if (!_listen_address.is_public())
                log::info(
                    logcat,
                    "Listening on private address {} with publicly reachable address {}",
                    _listen_address,
                    *_public_address);
            else
                // Binding to a different public IP/port than we actually advertise in RCs is not
                // allowed, as it is almost certainly a configuration error (e.g. such as moving the
                // config from one server to another and updating only one of the two values).
                throw std::runtime_error{
                    "public-ip/port ({}) and listen address ({}) are both public addresses but do not match!"_format(
                        _public_address, _listen_address)};

            log::info(
                log_global,
                "Session Router relay listening on {}{}",
                _listen_address,
                _public_address ? " with public address {}"_format(*_public_address) : "");
        }
        else  // Not a service node:
        {
            _listen_address = _config.links.listen_addr.value_or(DEFAULT_CLIENT_ADDR);

            // default listen port for clients is a specific port, we want 0 for embedded,
            // but perhaps the default should be 0 for all clients?
            if (!_config.links.listen_addr && embedded())
                _listen_address.set_port(0);

            log::info(log_global, "Session Router client connection using {}", _listen_address);
        }

        RelayContact::BLOCK_BOGONS = _config.router.block_bogons;

        auto& netconf = _config.network;

        if (!embedded())
        {
            assert(net());

            if (!netconf._if_name)
            {
                std::string suggest;
#ifdef __linux__
                if (is_service_node)
                {
                    // Use a name based on the hex pubkey prefix, for linux relays, which makes them
                    // easier to identify and associate with service ndoes when multiple are running.
                    const auto& rid = id();
                    suggest = "sr-tun@{}"_format(oxenc::to_hex(rid.data(), rid.data() + 4));
                }
#endif

                netconf._if_name = net()->find_free_tun(suggest);
            }

            if (netconf.ipv4_autoselect())
            {
                if (!netconf._reserved_local_ipv4.empty())
                    throw std::runtime_error{"[network]:mapaddr cannot be used with automatic IPv4 range selection"};
                log::info(logcat, "Session Router IPv4 local network will be auto-selected");

                if (!netconf._local_ip_net)
                    netconf._local_ip_net.emplace().mask = 16;
            }
            else
            {
                assert(netconf._local_ip_net);
                log::info(logcat, "Session Router IPv4 local network is {}", *netconf._local_ip_net);

                // Config should have already verified this, but just in case:
                std::erase_if(netconf._reserved_local_ipv4, [&netconf](const auto& addr_ip) {
                    return !netconf._local_ip_net->contains(addr_ip.second);
                });
            }

            if (netconf.ipv6_autoselect())
            {
                if (!netconf._reserved_local_ipv6.empty())
                    throw std::runtime_error{"[network]:mapaddr cannot be used with automatic IPv4 range selection"};
                log::info(logcat, "Session Router IPv6 local network will be auto-selected");

                if (!netconf._local_ipv6_net)
                    netconf._local_ipv6_net.emplace().mask = 64;
            }
            else
            {
                assert(netconf._local_ipv6_net);
                log::info(logcat, "Session Router IPv6 local network is {}", *netconf._local_ipv6_net);

                // Config should have already verified this, but just in case:
                std::erase_if(netconf._reserved_local_ipv6, [&netconf](const auto& addr_ip) {
                    return !netconf._local_ipv6_net->contains(addr_ip.second);
                });
            }
        }

        if (not is_service_node)
        {
            auto& pathconf = _config.paths;

            if (int conf_edges = static_cast<int>(_config.paths.strict_edges.size()); conf_edges > 0)
            {
                if (pathconf.edge_connections > conf_edges)
                {
                    log::warning(
                        logcat,
                        "[paths]:edge-connections is set to {0}, but only {1} strict edges are defined; lowering "
                        "edge-connections to {1}",
                        pathconf.edge_connections,
                        conf_edges);
                    pathconf.edge_connections = conf_edges;
                }
                else
                    log::debug(
                        logcat,
                        "Local client configured to maintain {} of {} possible strict edge relays",
                        pathconf.edge_connections,
                        conf_edges);
            }
            else
                log::debug(
                    logcat,
                    "Local client configured to maintain {} random router edge connections",
                    config().paths.edge_connections);

            // If any SRV records are pointing at localhost.loki, replace that with our actual
            // address
            for (auto& srv : netconf.srv_records)
            {
                if (srv.target == "localhost.{}"_format(CLIENT_TLD) || srv.target == "localhost.loki")
                    srv.target = "{}.{}"_format(id(), CLIENT_TLD);
            }
        }
    }

    void Router::configure()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        if (!embedded())
            sys::service_manager->starting();

        if (_config.exit.exit_enabled and is_service_node)
            throw std::runtime_error{
                "Session Router cannot simultaneously operate as a service node and client-operated exit node "
                "service!"};

        if (_config.oxend.disable_testing && netid() == NetID::MAINNET)
            throw std::runtime_error{"Error: reachability testing can only be disabled on testnet!"};

        auto net_id = netid();
        log::log(logcat, net_id == NetID::MAINNET ? log::Level::debug : log::Level::warn, "Network ID is {}", net_id);

        log::trace(logcat, "Configuring router...");

        log::info(log_global, "Operating as a Session Router {}", is_service_node ? "relay (service node)" : "client");

        if (rpc_backend)
        {
            if (is_service_node)
            {
                log::debug(logcat, "Starting oxend RPC client");
                _oxend = rpc_backend->make_oxend(*this, *_omq);
            }

            if (_config.api.enable_rpc_server)
            {
                log::debug(logcat, "Starting RPC server");
                _rpc_server = rpc_backend->make_rpc_server(*this, *_omq);
            }

            log::debug(logcat, "Starting OMQ server");
            rpc_backend->start_omq(*_omq);

            if (is_service_node)
            {
                log::debug(logcat, "Connecting to oxend @ {}", _config.oxend.rpc_addr);
                _oxend->connect_async(_config.oxend.rpc_addr);
            }
        }

        log::debug(logcat, "Initializing key manager");

        if (is_service_node)
            fetch_snode_keys();
        else
            key_manager = KeyManager{_config, is_service_node};

        log::trace(logcat, "Initializing from configuration");

        process_config();

        _node_db = std::make_unique<NodeDB>(*this);

        if (is_service_node)
        {
            // Wait, synchronously, for the oxend SN list update, for up to 10s.  If we still don't
            // get it, then fall back to using our current nodedb list.
            auto on_update = std::make_shared<std::promise<void>>();
            auto fut = on_update->get_future();
            _oxend->update_service_node_list(std::move(on_update));
            bool fallback = false;
            try
            {
                if (fut.wait_for(10s) == std::future_status::timeout)
                    throw std::runtime_error{"request timed out"};
                fut.get();
            }
            catch (std::exception& e)
            {
                log::warning(
                    log_global,
                    "Oxend SN request failed: {}. Proceeding with stored RC database as a fallback, which may be "
                    "out of date",
                    e.what());
                fallback = true;
            }

            if (fallback)
                _node_db->load_registered_relays_fallback();
        }

        _session_endpoint = std::make_unique<handlers::SessionEndpoint>(*this);

        log::debug(logcat, "Creating QUIC link manager");
        _link_manager = std::make_unique<link::Manager>(*this);
        _link_endpoint = &_link_manager->endpoint;

        if (!embedded())
        {
            log::debug(logcat, "Initializing TUN device");
            _tun = rpc_backend->make_tun(*this);

            log::info(logcat, "Session Router IPv4 local network is {}", _tun->get_ipv4_network());
            log::info(logcat, "Session Router IPv6 local network is {}", _tun->get_ipv6_network());

            // only (full) clients should have DNS, relays have no need for it
            if (!is_service_node)
                _dns = rpc_backend->make_dns(*this);

            log::info(
                log_global,
                "Session Router internal network: {} on device {}",
                _tun->get_ipv4_network(),
                _tun->get_if_name());
        }
        else
            log::debug(logcat, "Not initializing TUN device; running as an embedded client");
    }

    bool Router::is_exit_node() const { return _config.exit.exit_enabled; }

    bool Router::insufficient_peers() const
    {
        constexpr int KnownPeerWarningThreshold = 5;
        return node_db().num_rcs() < KnownPeerWarningThreshold;
    }

    std::optional<std::string> Router::OxendErrorState() const
    {
        // If we're in the registered list then we *should* be establishing connections to other
        // routers, so if we have almost no peers then something is almost certainly wrong.
        //
        // FIXME - this is disabled during Session Router optional transition so that new nodes that
        // can't yet connect to other network nodes don't prevent oxend from sending proofs.
        // TODO: uncomment this again once Session Router is mandatory (and the mandatory HF is live
        // on the network).
        /*
        if (insufficient_peers() and not _config.oxend.disable_testing)
            return "too few peer connections; Session Router is not adequately connected to the network";
        */
        return std::nullopt;
    }

    bool Router::appears_registered() const { return is_service_node and node_db().is_registered(id()); }

    void Router::regenerate_rc()
    {
        if (not appears_registered())
        {
            log::debug(logcat, "Not regenerating RC: not currently a registered service node");
            return;
        }

        RelayContact rc{*this};
        if (auto [stored, gossip] = _node_db->put_rc(std::move(rc)); gossip)
        {
            auto* rc = _node_db->get_rc(id());
            assert(rc);
            int count = _link_manager->gossip_rc(*rc);
            log::debug(logcat, "Regenerated RC and gossiped to {} peers", count);
        }
        else
        {
            log::debug(logcat, "NodeDB refused our own RC; perhaps we restarted too soon since the last regeneration?");
        }
    }

    bool Router::should_report_stats(steady_ms now) const
    {
        return uptime() >= 10s
            and now >= _last_stats_report
                + (log::get_level(logcat) <= log::Level::debug ? REPORT_STATS_INTERVAL_DEBUG : REPORT_STATS_INTERVAL);
    }

    std::string Router::_stats_line(sys_ms now) const
    {
        using namespace fmt::literals;
        auto [rcs, rids, bs] = _node_db->db_stats();
        auto [s_in, s_out_r, s_out_c, s_out_r_pending, s_out_c_pending] = _session_endpoint->session_stats();
        auto [in_paths, out_r_paths, out_c_paths] = _session_endpoint->path_stats(now);
        if (is_service_node)
        {
            auto [relays, rout, rin, rpending, clients] = link_endpoint().relay_connection_counts();
            return fmt::format(
                "relays: {relays} conns ({rin}↓, {rout}↑{pending}{full_mesh}), RC/RIDs: {rcs}/{rids}; "
                "{clients} clients; sessions: {sess_in}↓; paths: {paths_in}",

                "relays"_a = relays,
                "rin"_a = rin,
                "rout"_a = rout,
                "pending"_a = rpending ? ", {} pending"_format(rpending) : "",
                "full_mesh"_a = relays >= rids - 1 ? ", #" : "",
                "clients"_a = clients,
                "sess_in"_a = s_in,
                "paths_in"_a = in_paths,
                "rcs"_a = rcs,
                "rids"_a = rids);
        }

        auto [nconns, npending] = link_endpoint().client_connection_counts();
        return fmt::format(
            "conns: {conns}; sessions: {sess_in}↓/{sess_out_c}↑(c)/{sess_out_r}↑(r); "
            "paths: {paths_in}↓/{paths_out}↑, {path_percent:.1f}% of {path_total} attempts; "
            "RC/RIDs: {rcs}/{rids}",

            "conns"_a = nconns + npending,
            "sess_in"_a = s_in,
            "sess_out_c"_a = s_out_c,
            "sess_out_r"_a = s_out_r,
            "paths_in"_a = in_paths,
            "paths_out"_a = out_r_paths + out_c_paths,
            "path_percent"_a = (double)path_builds.success * 100.0 / (double)path_builds.attempts,
            "path_total"_a = path_builds.attempts,
            "rcs"_a = rcs,
            "rids"_a = rids);
    }

    void Router::report_stats()
    {
        const auto now = srouter::time_now_ms();

        log::info(log_global, "Local {}: {}", is_service_node ? "Relay" : "Client", _stats_line(now));

        _last_stats_report = steady_now_ms();

        oxen::log::flush();
    }

    std::string Router::status_line()
    {
        auto now = srouter::time_now_ms();
        return "v{} {}: {}"_format(
            fmt::join(srouter::VERSION, "."), is_service_node ? "relay" : "client", _stats_line(now));
    }

    void Router::_relay_tick([[maybe_unused]] sys_ms now)
    {
        assert(_config.type == config::Type::Relay);
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        auto steady_now = steady_now_ms();
        if (should_report_stats(steady_now))
            report_stats();

        bool registered = appears_registered();

        if (steady_now >= _next_dereg_warning)
        {
            if (not registered)
            {
                // complain about being deregistered/decommed
                log::error(logcat, "We are running as a relay but are not a registered service node");
                _next_dereg_warning = steady_now + DECOMM_WARNING_INTERVAL;
            }
            else if (insufficient_peers())
            {
                log::error(
                    logcat, "We are an active service node, but have too few ({}) known peers!", node_db().num_rcs());
                _next_dereg_warning = steady_now + DECOMM_WARNING_INTERVAL;
            }
        }

        if (registered)
        {
            int want = std::min(
                node_db().num_rcs(/*include_self=*/false) - link_endpoint().num_relay_conns(/*include_pending=*/true),
                RELAY_CONNECTS_PER_TICK);
            if (want > 0)
            {
                log::debug(logcat, "Service Node connecting to {} random routers to achieve full mesh", want);
                _link_manager->connect_to_keep_alive(want);
            }
        }

        path_context.expire_hops(now);
    }

    void Router::_client_tick(sys_ms now)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        _router_profiling.tick();

        auto steady_now = steady_now_ms();
        if (should_report_stats(steady_now))
            report_stats();

        // if we need more sessions to routers we shall connect out to others
        if (int n_conns = link_endpoint().num_relay_conns(/*include_pending=*/true);
            n_conns < config().paths.edge_connections)
        {
            auto num_needed = config().paths.edge_connections - n_conns;

            log::debug(
                logcat,
                "Client connecting to {} random routers to keep alive (current:{}, target:{})",
                num_needed,
                n_conns,
                config().paths.edge_connections);
            _link_manager->connect_to_keep_alive(num_needed);
        }

        _session_endpoint->tick(now);
    }

    void Router::tick()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_is_stopping)
        {
            log::debug(logcat, "Router is stopping; exiting ::tick()...");
            return;
        }

        const auto now = time_now_ms();
        const auto steady_now = steady_now_ms();

        if (const auto delta = steady_now - _last_tick;
            _last_tick != steady_ms{} and (delta > NETWORK_RESET_SKIP_INTERVAL || delta < -NETWORK_RESET_SKIP_INTERVAL))
        {
            // TODO: this, if needed?
            // we detected a time skip into the futre, thaw the network
            log::error(logcat, "Timeskip of {}ms detected, resetting network state!", delta.count());
        }

        if (is_service_node)
            _relay_tick(now);
        else
            _client_tick(now);

        // update tick timestamp
        _last_tick = steady_now_ms();
    }

    void Router::start()
    {
        log::debug(logcat, "{} called", __PRETTY_FUNCTION__);

        if (is_service_node)
        {
            log::debug(logcat, "Router accepting transit traffic");
            path_context.allow_transit();

            // relays do not use profiling
            _router_profiling.disable();
        }
        else if (netid() == NetID::MAINNET and _config.network.enable_profiling)
        {
            _router_profiling._profile_file = _config.router.data_dir / "profiles.dat";

            log::debug(logcat, "Router profiling enabled");
            if (not std::filesystem::exists(_router_profiling._profile_file))
            {
                log::debug(logcat, "No profiles file found at {}; skipping...", _router_profiling._profile_file);
            }
            else
            {
                log::debug(logcat, "Loading router profiles from {}", _router_profiling._profile_file);
                _router_profiling.load_from_disk();
            }

            if (_config.network.save_profiles)
            {
                log::debug(logcat, "Router profile saving enabled");
                _router_profiling.start_save_timer(*this);
            }
        }
        else
        {
            _config.network.enable_profiling = false;
            _router_profiling.disable();
            log::info(logcat, "Router profiling disabled");
        }

        log::debug(logcat, "Starting Router main tick interval");
        _tick_timer = _jq->add_timer(ROUTER_TICK_INTERVAL, [this] { tick(); });

        start_timers();
        _is_running = true;

        if (!embedded())
            srouter::sys::service_manager->ready();

        log::info(
            log_global,
            "{} started @ {}",
            is_service_node ? "Relay" : "Client",
            id().to_network_address(is_service_node));

        // Fire a tick right now to start making connections immediately (rather than waiting until
        // the first tick):
        tick();
    }

    bool Router::is_edge_connected() const
    {
        return _jq->call_get([this] { return _is_edge_connected; });
    }
    bool Router::is_path_connected() const
    {
        return _jq->call_get([this] { return _is_edge_connected && _has_established_paths; });
    }

    void Router::on_connected(std::function<void()> callback, bool with_paths, bool persistent)
    {
        if (!callback)
            return;
        _jq->call([this, with_paths, callback = std::move(callback), persistent] {
            bool fire_now = _is_edge_connected && (_has_established_paths || !with_paths);
            if (fire_now)
                try_calling(logcat, callback);

            if (persistent || !fire_now)
                (with_paths ? _on_path_connected : _on_edge_connected).emplace_back(std::move(callback), persistent);
        });
    }

    void Router::on_disconnected(std::function<void()> callback, bool with_paths, bool persistent)
    {
        if (!callback)
            return;
        _jq->call([this, callback = std::move(callback), persistent, with_paths] {
            bool fire_now = !_is_edge_connected || (with_paths && !_has_established_paths);
            if (fire_now)
                try_calling(logcat, callback);

            if (persistent || !fire_now)
                (with_paths ? _on_path_disconnected : _on_path_connected).emplace_back(std::move(callback), persistent);
        });
    }

    static void process_on_conn_callbacks(std::list<std::pair<std::function<void()>, bool>> callbacks)
    {
        for (auto it = callbacks.begin(); it != callbacks.end();)
        {
            auto& [f, persist] = *it;
            try_calling(logcat, f);
            if (persist)
                ++it;
            else
                it = callbacks.erase(it);
        }
    }

    void Router::on_edge_conn_change()
    {
        assert(_loop->inside());

        int conns = link_endpoint().num_relay_conns();
        if (conns == 0 and _is_edge_connected)
        {
            _is_edge_connected = false;

            log::warning(log_global, "Session Router is no longer connected to the network!");

            process_on_conn_callbacks(_on_path_disconnected);
            process_on_conn_callbacks(_on_edge_disconnected);
        }
        else if (
            not _is_edge_connected
            and conns * CLIENT_CONNECTED_THRESHOLD::den
                >= config().paths.edge_connections * CLIENT_CONNECTED_THRESHOLD::num)
        {
            _is_edge_connected = true;

            log::info(
                log_global,
                "Session Router is now connected to the network ({}) with {}/{} relay connections",
                config().network.is_reachable ? id().to_network_address(false).to_string() : "outgoing-only",
                conns,
                config().paths.edge_connections);

            process_on_conn_callbacks(_on_edge_connected);
            if (_has_established_paths)
                process_on_conn_callbacks(_on_path_connected);
        }
    }

    void Router::on_inbound_path_change(bool connected)
    {
        if (connected == _has_established_paths)
            return;

        _has_established_paths = connected;

        if (_has_established_paths)
        {
            if (!_is_edge_connected)
            {
                // If we aren't edge connected then an established path isn't enough to push us into
                // "path connected" state, so do nothing for now aside from setting the cool.  When
                // we hit edge connected state (above) it will fire the _on_path_connected callbacks.
                return;
            }

            process_on_conn_callbacks(_on_path_connected);
        }
        else
        {
            if (!_is_edge_connected)
            {
                // If we already lost all our edges then the path disconnected callbacks were
                // already fired as part of that, so we don't need to call them now.
                return;
            }

            process_on_conn_callbacks(_on_path_disconnected);
        }
    }

    void Router::on_test_ping()
    {
        if (_router_testing)
            _router_testing->incoming_ping();
    }

    void Router::stop()
    {
        if (!_is_running)
        {
            log::debug(logcat, "Stop called, but not running");
            return;
        }
        if (_is_stopping)
        {
            log::debug(logcat, "Stop called, but already stopping");
            return;
        }

        if (_is_stopping.exchange(true))
            return;  // Lost a race with something else trying to stop

        _jq->call([this] {
            if (!embedded())
            {
                log::debug(logcat, "stopping service manager...");
                srouter::sys::service_manager->stopping();
            }

            if (_router_testing)
                _router_testing->stop();

            _session_endpoint->stop(true);

            if (not is_service_node)
                _router_profiling.stop_save_timer();

            log::debug(logcat, "closing all connections");
            _link_manager->stop();

            if (_dns)
                _dns.reset();

            if (_tun)
                _tun->stop();

            auto rv = _jq->remove(_tick_timer);
            log::debug(logcat, "router tick timer stopped {}successfully!", rv ? "" : "un");
            _tick_timer = {};

            if (_service_stat_timer)
            {
                rv = _jq->remove(_service_stat_timer);
                log::debug(logcat, "service stat timer stopped {}successfully!", rv ? "" : "un");
                _service_stat_timer = {};
            }

            if (_gossip_timer)
            {
                log::debug(logcat, "clearing RC regen timer...");
                _jq->remove(_gossip_timer);
                _gossip_timer = {};
            }

            log::debug(logcat, "stopping nodedb events");
            node_db().cleanup();

            // Submit a dummy job to the disk loop that we wait on to ensure that we've cleared out
            // any pending disk write jobs.
            log::debug(logcat, "flushing disk loop jobs");
            disk_loop.call_get([] {});

            log::debug(logcat, "cleaning up link_manager");
            _link_endpoint = nullptr;
            _link_manager.reset();

            if (_tun)
                _tun.reset();

            if (_router_close_cb)
                _router_close_cb();

            _is_running.store(false);

            _omq.reset();

            _close_promise.set_value();
            log::info(log_global, "Session Router has stopped");
        });
    }

    std::pair<std::optional<NetworkAddress>, bool> Router::reverse_lookup(const ipv4& addr) const
    {
        if (_tun)
            return _tun->reverse_lookup(addr);
        return {std::nullopt, false};
    }

    std::pair<std::optional<NetworkAddress>, bool> Router::reverse_lookup(const ipv6& addr) const
    {
        if (_tun)
            return _tun->reverse_lookup(addr);
        return {std::nullopt, false};
    }

    const srouter::net::Platform* Router::net() const
    {
        if (embedded())
            return nullptr;
        return srouter::net::native_net_platform;
    }

}  // namespace srouter
