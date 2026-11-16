#include "rpc_server.hpp"

#include "config/config.hpp"
#include "constants/version.hpp"
#include "contact/client_contact.hpp"
#include "link/link_manager.hpp"
#include "router/router.hpp"
#include "rpc/rpc_request_definitions.hpp"
#include "rpc_request.hpp"

#include <nlohmann/json.hpp>
#include <oxenc/base32z.h>

#include <exception>
#include <set>
#include <vector>

namespace srouter::rpc
{
    static auto logcat = srouter::log::Cat("rpc-server");

    template <typename T>
        requires std::derived_from<T, RPCRequest>
    static void log_print_rpc(T& req)
    {
        log::info(logcat, "RPC Server received request for endpoint `{}`", req.name);
    }

#if 0
    // Fake packet source that serializes repsonses back into dns
    class DummyPacketSource final : public dns::PacketSource
    {
        std::function<void(std::optional<dns::Message>)> func;

      public:
        explicit DummyPacketSource(std::function<void(std::optional<dns::Message>)> func) : func{std::move(func)} {}

        bool would_loop(const quic::Address&, const quic::Address&) const override { return false; };

        /// send packet with src and dst address containing buf on this packet source
        void send_udp(const quic::Address&, const quic::Address&, std::span<const std::byte> payload) const override
        {
            func(dns::Message::extract(payload));
        }

        /// returns the sockaddr we are bound on if applicable
        std::optional<quic::Address> bound_on() const override { return std::nullopt; }
    };
#endif

    bool check_path(std::string path)
    {
        for (auto c : path)
        {
            if (not((c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c == '_')
                    or (c == '-')))
            {
                return false;
            }
        }

        return true;
    }

    template <typename RPC>
    void register_rpc_command(std::unordered_map<std::string, rpc_callback>& regs)
    {
        static_assert(std::is_base_of_v<RPCRequest, RPC>);
        rpc_callback cback{};

        cback.invoke = make_invoke<RPC>();

        regs.emplace(RPC::name, std::move(cback));
    }

    RPCServer::RPCServer(oxenmq::OxenMQ& omq, Router& r) : _omq{omq}, _router(r)
    {
        if (srouter::logRingBuffer)
            log_subs.emplace(_omq, srouter::logRingBuffer);

        for (const auto& addr : _router.config().api.rpc_bind_addrs)
        {
            // The llarp category (MapExit and friends) requires admin.  An IPC socket is guarded by
            // its file permissions, and OxenMQ doesn't get a usable address for its peers, so every
            // IPC connection gets admin.  Over TCP only loopback peers do.
            const bool ipc = addr.starts_with("ipc://");
            _omq.listen_plain(addr, [ipc](std::string_view remote, std::string_view /*pubkey*/, bool /*sn*/) {
                if (ipc or remote.starts_with("127.") or remote == "::1")
                    return oxenmq::AuthLevel::admin;
                return oxenmq::AuthLevel::denied;
            });
            log::debug(logcat, "Bound RPC server to {} (admin for loopback/IPC only)", addr);
        }

        AddCategories();
    }

    template <typename... RPC>
    std::unordered_map<std::string, rpc_callback> register_rpc_requests(tools::type_list<RPC...>)
    {
        std::unordered_map<std::string, rpc_callback> regs;

        (register_rpc_command<RPC>(regs), ...);

        return regs;
    }

    const std::unordered_map<std::string, rpc_callback> rpc_request_map =
        register_rpc_requests(rpc::rpc_request_types{});

    void RPCServer::AddCategories()
    {
        // AuthLevel::admin: MapExit/UnmapExit/SwapExits (and other llarp commands) are not
        // freely usable once the API is bound.  Loopback/IPC connections are granted admin
        // by the listen_plain AllowFunc above.  Do not lower this back to none.
        _omq.add_category("llarp", oxenmq::AuthLevel::admin).add_request_command("logs", [this](oxenmq::Message& msg) {
            HandleLogsSubRequest(msg);
        });

        for (auto& req : rpc_request_map)
        {
            _omq.add_request_command(
                "llarp", req.first, [name = std::string_view{req.first}, &call = req.second, this](oxenmq::Message& m) {
                    call.invoke(m, *this);
                });
        }
    }

    void RPCServer::invoke(Halt& halt)
    {
        log_print_rpc(halt);

        if (not _router.is_running())
        {
            SetJSONError("Router is not running", halt.response);
            return;
        }

        _router._jq->call_soon([&]() { _router.stop(); });

        SetJSONResponse("OK", halt.response);
    }

    void RPCServer::invoke(Version& version)
    {
        log_print_rpc(version);

        nlohmann::json result{
            {"version", srouter::VERSION}, {"version_full", srouter::VERSION_FULL}, {"uptime", to_json(uptime())}};

        SetJSONResponse(result, version.response);
    }

    void RPCServer::invoke(Status& status)
    {
        log_print_rpc(status);

        // TODO: this
    }

    void RPCServer::invoke(GetStatus& getstatus)
    {
        log_print_rpc(getstatus);

        // TODO: this
    }

    void RPCServer::invoke(QuicConnect& quicconnect)
    {
        log_print_rpc(quicconnect);

        auto& req = quicconnect.request;

        if (req.port == 0 and req.closeID == 0)
        {
            SetJSONError("Port not provided", quicconnect.response);
            return;
        }

        if (req.remoteHost.empty() and req.closeID == 0)
        {
            SetJSONError("Host not provided", quicconnect.response);
            return;
        }

        // auto endpoint =
        //     (req.endpoint.empty()) ? GetEndpointByName(_router, "default") : GetEndpointByName(_router,
        //     req.endpoint);

        // if (not endpoint)
        // {
        //     SetJSONError("No such local endpoint found.", quicconnect.response);
        //     return;
        // }

        // auto quic = endpoint->GetQUICTunnel();

        // if (not quic)
        // {
        //     SetJSONError("No quic interface available on endpoint " + req.endpoint, quicconnect.response);
        //     return;
        // }

        if (req.closeID)
        {
            // TODO:
            // quic->forget(req.closeID);
            SetJSONResponse("OK", quicconnect.response);
            return;
        }

        quic::Address laddr{req.bindAddr, req.port};

        try
        {
            // TODO:
            // auto [addr, id] = quic->open(
            //     req.remoteHost, req.port, [](auto&&) {}, laddr);

            nlohmann::json status;
            // status["addr"] = addr.to_string();
            // status["id"] = id;

            SetJSONResponse(status, quicconnect.response);
        }
        catch (std::exception& e)
        {
            SetJSONError(e.what(), quicconnect.response);
        }
    }

    void RPCServer::invoke(QuicListener& quiclistener)
    {
        log_print_rpc(quiclistener);

        auto req = quiclistener.request;

        if (req.port == 0 and req.closeID == 0)
        {
            SetJSONError("Invalid arguments", quiclistener.response);
            return;
        }

        // auto endpoint =
        //     (req.endpoint.empty()) ? GetEndpointByName(_router, "default") : GetEndpointByName(_router,
        //     req.endpoint);

        // if (not endpoint)
        // {
        //     SetJSONError("No such local endpoint found", quiclistener.response);
        //     return;
        // }

        // auto quic = endpoint->GetQUICTunnel();

        // if (not quic)
        // {
        //     SetJSONError("No quic interface available on endpoint " + req.endpoint, quiclistener.response);
        //     return;
        // }

        if (req.closeID)
        {
            // TODO:
            // quic->forget(req.closeID);
            SetJSONResponse("OK", quiclistener.response);
            return;
        }

        if (req.port)
        {
            auto id = 0;
            try
            {
                quic::Address addr{req.remoteHost, req.port};
                // TODO:
                // id = quic->listen(addr);
            }
            catch (std::exception& e)
            {
                SetJSONError(e.what(), quiclistener.response);
                return;
            }

            nlohmann::json result;
            result["id"] = id;
            std::string localAddress;
            // var::visit([&](auto&& addr) { localAddress = addr.to_string(); }, endpoint->local_address());
            result["addr"] = localAddress + ":" + std::to_string(req.port);

            if (not req.srvProto.empty())
            {
                dns::SRVData srvData{req.srvProto, 1, 1, req.port, ""};
                // endpoint->put_srv_record(std::move(srvData));
            }

            SetJSONResponse(result, quiclistener.response);
            return;
        }
    }

    static std::optional<NetworkAddress> try_netaddr(std::string_view x)
    {
        try
        {
            return NetworkAddress{x};
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    void RPCServer::invoke(FindCC& findcc)
    {
        log_print_rpc(findcc);

        if (_router.is_service_node)
        {
            SetJSONError("Not supported", findcc.response);
            return;
        }

        if (findcc.request.pk.empty())
        {
            SetJSONError("No pubkey provided!", findcc.response);
            return;
        }

        auto maybe_netaddr = try_netaddr(findcc.request.pk);

        if (not maybe_netaddr)
        {
            SetJSONError("Invalid pubkey provided: {}"_format(findcc.request.pk), findcc.response);
            return;
        }

        _router._jq->call([this, netaddr = *maybe_netaddr, replier = findcc.move()]() mutable {
            _router.session_endpoint().lookup_client_intro(
                netaddr.pubkey, [&replier](std::optional<srouter::ClientContact> cc) {
                    nlohmann::json result;
                    if (cc)
                    {
                        auto cc_str = "{}"_format(*cc);
                        result.emplace("cc", cc_str);
                        log::info(logcat, "RPC call to `find_cc` returned successfully: {}", cc_str);
                    }
                    else
                    {
                        log::warning(logcat, "RPC call to `find_cc` failed!");
                        result.emplace("cc", "ERROR");
                    }
                    replier.reply(result.dump());
                });
        });
    }

    void RPCServer::invoke(SessionInit& sessioninit)
    {
        log_print_rpc(sessioninit);

        if (_router.is_service_node)
        {
            SetJSONError("Not supported", sessioninit.response);
            return;
        }

        if (sessioninit.request.pk.empty())
        {
            SetJSONError("No pubkey provided!", sessioninit.response);
            return;
        }

        auto maybe_netaddr = try_netaddr(sessioninit.request.pk);

        if (not maybe_netaddr)
        {
            SetJSONError("Invalid pubkey provided: {}"_format(sessioninit.request.pk), sessioninit.response);
            return;
        }

        _router._jq->call([this, netaddr = *maybe_netaddr]() {
            try
            {
                log::debug(logcat, "Beginning session init to remote instance: {}", netaddr);
                _router.session_endpoint().initiate_remote_session(netaddr, nullptr);
                /*[replier = sessioninit.move()](auto success) mutable {
                    // FIXME: needs redone, initiate remote session no longer returns an ip
                    nlohmann::json result;
                    std::string a = std::holds_alternative<ipv4>(ip) ? std::get<ipv4>(ip).to_string()
                                                                     : std::get<ipv6>(ip).to_string();
                    result.emplace("ip", a);
                    log::info(logcat, "RPC call to `session_init` succeeded: {}", a);
                    replier.reply(result.dump());
                });
                */
                log::info(logcat, "RPC Server dispatched `session_init` to remote:{}", netaddr);
            }
            catch (const std::exception& e)
            {
                log::critical(logcat, "Failed to parse remote instance netaddr: {}", e.what());
            }
        });
    }

    void RPCServer::invoke(SessionClose& sessionclose)
    {
        log_print_rpc(sessionclose);

        if (sessionclose.request.pk.empty())
        {
            SetJSONError("No pubkey provided!", sessionclose.response);
            return;
        }

        auto maybe_netaddr = try_netaddr(sessionclose.request.pk);

        if (not maybe_netaddr)
        {
            SetJSONError("Invalid pubkey provided: {}"_format(sessionclose.request.pk), sessionclose.response);
            return;
        }

        auto& netaddr = *maybe_netaddr;

        _router._jq->call([&]() {
            try
            {
                if (auto session = _router.session_endpoint().get_session(netaddr))
                {
                    auto hook = [replier = sessionclose.move()](quic::message m) mutable {
                        nlohmann::json result;

                        if (m)
                        {
                            result.emplace("result", "OK");
                            log::info(logcat, "RPC call to `session_close` succeeded!");
                            return replier.reply(result.dump());
                        }

                        std::string status{"<none given>"};

                        try
                        {
                            oxenc::bt_dict_consumer btdc{m.body()};

                            if (auto s = btdc.maybe<std::string>("!"sv))
                                status = std::move(*s);
                        }
                        catch (const std::exception& e)
                        {
                            status = "Exception: {}"_format(e.what());
                        }

                        log::critical(logcat, "Call to `session_close` FAILED; reason: {}", status);
                        result.emplace("result", std::move(status));
                        replier.reply(result.dump());
                    };

                    // session->stop_session(true, std::move(hook));

                    log::info(logcat, "RPC Server dispatched `session_close` to remote:{}", netaddr);
                }
            }
            catch (const std::exception& e)
            {
                log::critical(logcat, "Failed to parse remote instance netaddr: {}", e.what());
            }
        });
    }

    // TODO: fix this because it's bad
    void RPCServer::invoke(LookupSnode& lookupsnode)
    {
        log_print_rpc(lookupsnode);

        if (not _router.is_service_node)
        {
            SetJSONError("Not supported", lookupsnode.response);
            return;
        }

        RouterID routerID;

        if (lookupsnode.request.routerID.empty())
        {
            SetJSONError("No remote ID provided", lookupsnode.response);
            return;
        }

        if (not routerID.from_relay_address(lookupsnode.request.routerID))
        {
            SetJSONError("Invalid remote: " + lookupsnode.request.routerID, lookupsnode.response);
            return;
        }

        // _router.loop()->call([&]() {
        //   auto endpoint = _router.exit_context().get_exit_endpoint("default");

        //   if (endpoint == nullptr)
        //   {
        //     SetJSONError("Cannot find local endpoint: default", lookupsnode.response);
        //     return;
        //   }

        //   endpoint->ObtainSNodeSession(routerID, [&](auto session) {
        //     if (session and session->IsReady())
        //     {
        //       const auto ip = net::TruncateV6(endpoint->GetIPForIdent(PubKey{routerID}));
        //       nlohmann::json status{{"ip", ip.to_string()}};
        //       SetJSONResponse(status, lookupsnode.response);
        //       return;
        //     }

        //     SetJSONError("Failed to obtain snode session", lookupsnode.response);
        //     return;
        //   });
        // });
    }

    namespace
    {
        // Privacy profile: MapExit accepts IP CIDRs only. Reject hostname-looking entries
        // (alpha chars that do not parse as IPv4/IPv6 CIDR — IPv6 hex a-f still OK).
        bool ip_range_looks_like_hostname(std::string_view rstr)
        {
            bool has_alpha = false;
            for (char c : rstr)
            {
                if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z'))
                {
                    has_alpha = true;
                    break;
                }
            }
            if (not has_alpha)
                return false;
            try
            {
                if (rstr.find(':') != std::string_view::npos)
                    (void)parse_ipv6_range(rstr, 128);
                else
                    (void)parse_ipv4_range(rstr, 32);
                return false;  // parsed as CIDR (e.g. IPv6 with hex letters)
            }
            catch (const std::exception&)
            {
                return true;
            }
        }

        // Parses MapExit/SwapExits ranges.  full_tunnel=true maps 0.0.0.0/0 and ::/0, and cannot be
        // combined with specific ranges; without it, ip_ranges must be non-empty and contain no /0.
        std::vector<std::variant<ipv4_range, ipv6_range>> build_exit_ranges(
            const std::vector<std::string>& ip_ranges, bool full_tunnel)
        {
            std::vector<std::variant<ipv4_range, ipv6_range>> out;
            for (const auto& rstr : ip_ranges)
            {
                if (ip_range_looks_like_hostname(rstr))
                    throw std::invalid_argument{"ip_ranges must be IP ranges; hostname rejected: {}"_format(rstr)};
                std::variant<ipv4_range, ipv6_range> parsed;
                if (rstr.find(':') != std::string::npos)
                    parsed = parse_ipv6_range(rstr, 128);
                else
                    parsed = parse_ipv4_range(rstr, 32);
                const bool is_all = std::visit([](const auto& r) { return r.mask == 0; }, parsed);
                if (is_all and not full_tunnel)
                    throw std::invalid_argument{"{} requires full_tunnel=true"_format(rstr)};
                if (full_tunnel and not is_all)
                    throw std::invalid_argument{"full_tunnel=true cannot be combined with {}"_format(rstr)};
                out.push_back(std::move(parsed));
            }
            if (full_tunnel)
                return {ipv4{0} / 0, ipv6{} / 0};
            if (out.empty())
                throw std::invalid_argument{"ip_ranges is empty: list ranges, or pass full_tunnel=true"};
            return out;
        }

        NetworkAddress parse_exit_address(const std::string& addr)
        {
            if (addr.empty())
                throw std::invalid_argument{"exit address (.{}) required"_format(CLIENT_TLD)};
            NetworkAddress exit_addr{addr};
            if (not exit_addr.client())
                throw std::invalid_argument{"exit address must be a .{} address"_format(CLIENT_TLD)};
            return exit_addr;
        }

        void start_exit_session(Router& router, const NetworkAddress& exit_addr)
        {
            try
            {
                router.session_endpoint().initiate_remote_session(exit_addr, nullptr);
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Could not start session to exit {}: {}", exit_addr, e.what());
            }
        }
    }  // namespace

    // The exit mappings, session state and OS routes all belong to the router loop, so the
    // handlers below do their work there and reply once it is done.

    void RPCServer::invoke(MapExit& mapexit)
    {
        log_print_rpc(mapexit);

        try
        {
            auto exit_addr = parse_exit_address(mapexit.request.address);
            auto built = build_exit_ranges(mapexit.request.ip_ranges, mapexit.request.full_tunnel);
            const auto count = built.size();

            _router._jq->call_get([&] {
                _router.session_endpoint().set_auth_token(exit_addr, mapexit.request.token);
                _router.mutable_exit_ranges()[exit_addr] = std::move(built);
                start_exit_session(_router, exit_addr);
                _router.exit_map_changed();
            });

            log::info(logcat, "Mapped {} range(s) via exit {}", count, exit_addr);
            SetJSONResponse("mapped {} range(s) via {}"_format(count, exit_addr), mapexit.response);
        }
        catch (const std::exception& e)
        {
            SetJSONError(e.what(), mapexit.response);
        }
    }

    void RPCServer::invoke(ListExits& listexits)
    {
        log_print_rpc(listexits);

        auto exits = _router._jq->call_get([this] {
            nlohmann::json exits = nlohmann::json::array();
            for (const auto& [addr, range_list] : _router.exit_ranges())
            {
                nlohmann::json entry;
                entry["address"] = addr.to_string();
                nlohmann::json rs = nlohmann::json::array();
                for (const auto& r : range_list)
                    rs.push_back(std::visit([](const auto& rr) { return rr.to_string(); }, r));
                entry["ranges"] = std::move(rs);
                if (auto* s = _router.session_endpoint().get_session(addr))
                {
                    entry["session_live"] = true;
                    entry["exit_capable"] = s->is_exit_capable;
                    entry["last_activity"] = s->last_activity_at().time_since_epoch().count();
                }
                else
                {
                    entry["session_live"] = false;
                    entry["exit_capable"] = false;
                }
                exits.push_back(std::move(entry));
            }
            return exits;
        });
        SetJSONResponse(exits, listexits.response);
    }

    void RPCServer::invoke(FirstHops& firsthops)
    {
        log_print_rpc(firsthops);

        auto addrs = _router._jq->call_get([this] { return _router.link_manager().endpoint.first_hop_addrs(); });
        std::set<std::string> hosts;
        for (const auto& a : addrs)
            hosts.insert(a.host());

        SetJSONResponse(nlohmann::json{{"first_hops", hosts}}, firsthops.response);
    }

    void RPCServer::invoke(UnmapExit& unmapexit)
    {
        log_print_rpc(unmapexit);

        try
        {
            if (unmapexit.request.address.empty())
                throw std::invalid_argument{"address required"};
            NetworkAddress exit_addr{unmapexit.request.address};

            bool erased = _router._jq->call_get([&] {
                if (_router.mutable_exit_ranges().erase(exit_addr) == 0)
                    return false;
                _router.exit_map_changed();
                return true;
            });
            if (not erased)
                throw std::invalid_argument{"no mapping for that address"};

            log::info(logcat, "Unmapped exit {}", exit_addr);
            SetJSONResponse("OK", unmapexit.response);
        }
        catch (const std::exception& e)
        {
            SetJSONError(e.what(), unmapexit.response);
        }
    }

    //  Replaces the mapping for exit_addresses[0] with one for exit_addresses[1] in one step.
    //  [A, A] remaps A.
    void RPCServer::invoke(SwapExits& swapexits)
    {
        log_print_rpc(swapexits);

        try
        {
            if (swapexits.request.exit_addresses.size() != 2)
                throw std::invalid_argument{"exit_addresses must be [old, new]"};
            auto old_addr = parse_exit_address(swapexits.request.exit_addresses[0]);
            auto new_addr = parse_exit_address(swapexits.request.exit_addresses[1]);
            auto built = build_exit_ranges(swapexits.request.ip_ranges, swapexits.request.full_tunnel);
            const auto count = built.size();

            bool swapped = _router._jq->call_get([&] {
                auto& ranges = _router.mutable_exit_ranges();
                if (ranges.erase(old_addr) == 0)
                    return false;
                _router.session_endpoint().set_auth_token(new_addr, swapexits.request.token);
                ranges[new_addr] = std::move(built);
                start_exit_session(_router, new_addr);
                _router.exit_map_changed();
                return true;
            });
            if (not swapped)
                throw std::invalid_argument{"no mapping for exit_addresses[0]"};

            log::info(logcat, "Swapped exit {} for {} ({} range(s))", old_addr, new_addr, count);
            SetJSONResponse("swapped {} -> {} ({} range(s))"_format(old_addr, new_addr, count), swapexits.response);
        }
        catch (const std::exception& e)
        {
            SetJSONError(e.what(), swapexits.response);
        }
    }

#if 0
    void RPCServer::invoke(DNSQuery& dnsquery)
    {
        log_print_rpc(dnsquery);

        std::string qname = (dnsquery.request.qname.empty()) ? "" : dnsquery.request.qname;
        dns::QType_t qtype = (dnsquery.request.qtype) ? dnsquery.request.qtype : dns::qTypeA;

        dns::Message msg{dns::Question{qname, qtype}};

        // auto endpoint = (dnsquery.request.endpoint.empty()) ? GetEndpointByName(_router, "default")
        //                                                     : GetEndpointByName(_router, dnsquery.request.endpoint);

        // if (endpoint == nullptr)
        // {
        //     SetJSONError("No such endpoint found for dns query", dnsquery.response);
        //     return;
        // }

        // if (auto dns = endpoint->DNS())
        // {
        //     auto packet_src = std::make_shared<DummyPacketSource>([&](auto result) {
        //         if (result)
        //             SetJSONResponse(result->ToJSON(), dnsquery.response);
        //         else
        //             SetJSONError("No response from DNS", dnsquery.response);
        //     });
        //     if (not dns->maybe_handle_packet(packet_src, packet_src->dumb, packet_src->dumb,
        //     IPPacket{msg.to_buffer()}))
        //         SetJSONError("DNS query not accepted by endpoint", dnsquery.response);
        // }
        // else
        //     SetJSONError("Endpoint does not have dns", dnsquery.response);
        return;
    }
#endif

    void RPCServer::HandleLogsSubRequest(oxenmq::Message& m)
    {
        if (m.data.size() != 1)
        {
            m.send_reply("Invalid subscription request: no log receipt endpoint given");
            return;
        }

        if (!log_subs)
        {
            m.send_reply("This Session Router instance is not capturing logs");
            return;
        }

        auto endpoint = std::string{m.data[0]};

        if (endpoint == "unsubscribe")
        {
            log::debug(logcat, "New logs unsubscribe request from conn {}@{}", m.conn.to_string(), m.remote);
            log_subs->unsubscribe(m.conn);
            m.send_reply("OK");
            return;
        }

        auto is_new = log_subs->subscribe(m.conn, endpoint);

        if (is_new)
        {
            log::debug(logcat, "New logs subscription request from conn {}@{}", m.conn.to_string(), m.remote);
            m.send_reply("OK");
            log_subs->send_all(m.conn, endpoint);
        }
        else
        {
            log::debug(logcat, "Renewed logs subscription request from conn id {}@{}", m.conn.to_string(), m.remote);
            m.send_reply("ALREADY");
        }
    }

}  // namespace srouter::rpc
