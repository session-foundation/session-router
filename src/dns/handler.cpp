
#include "handler.hpp"

#include "dns/rr.hpp"
#include "flags.hpp"
#include "message.hpp"
#include "nodedb.hpp"
#include "router/router.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"

#include <ranges>

namespace srouter::dns
{
    namespace
    {
        auto logcat = log::Cat("dns");

        const auto random_snode = "random.{}"_format(RELAY_TLD);

        const auto localhost_ctld = "localhost.{}"_format(CLIENT_TLD);
        const auto dot_localhost_ctld = ".localhost.{}"_format(CLIENT_TLD);
        bool is_localhost(std::string_view qname)
        {
            return qname == "localhost.loki" or qname.ends_with(".localhost.loki") or qname == localhost_ctld
                or qname.ends_with(dot_localhost_ctld);
        }

        std::optional<RouterID> parse_rid(std::string_view b32rid)
        {
            auto rid = std::make_optional<RouterID>();
            if (not rid->from_base32z(b32rid))
                rid.reset();
            return rid;
        }

        std::optional<RouterID> is_snode(std::string_view name)
        {
            if (name.ends_with(RELAY_DOT_TLD))
                name.remove_suffix(RELAY_DOT_TLD.size());
            else
                return std::nullopt;
            return parse_rid(name);
        }

        template <typename T, typename... Args>
        std::optional<T> try_making(Args&&... args)
        {
            try
            {
                return std::make_optional<T>(std::forward<Args>(args)...);
            }
            catch (...)
            {
                return std::nullopt;
            }
        }

    }  // namespace

    RequestHandler::RequestHandler(Router& router) : _router{router}
    {
        if (!_router.tun_endpoint())
            throw std::logic_error{"dns::RequestHandler requires a TUN endpoint"};

        if (!_router.config().dns._upstream_dns.empty())
            _unbound.emplace(_router);
    }

    void RequestHandler::operator()(
        std::span<const std::byte> request, const quic::Address& from, ReplyCallback reply, bool tcp)
    {
        std::span<const std::byte> client_ip;
        if (from.is_ipv4())
            client_ip = {reinterpret_cast<const std::byte*>(&from.in4().sin_addr.s_addr), 4};
        else
            client_ip = {reinterpret_cast<const std::byte*>(from.in6().sin6_addr.s6_addr), 16};

        auto maybe = Message::extract_question(request, _cookie_secret, client_ip);
        if (not maybe)
        {
            log::warning(logcat, "Ignoring unparseable DNS request from {}", from);
            return;
        }
        auto& msg = *maybe;

        if (msg.bad_extract)
        {
            reply(msg.encode(tcp));
            return;
        }

        if (msg.additional_edns && msg.additional_edns->bad_cookie)
        {
            // Client gave a bad cookie; reply with a request failure, but one containing the new
            // cookie so that the client can retry.

            // The lower 4 bits of the BADCOOKIE code go here; the upper 8 bits are in the OPT EDNS
            // value.
            msg.hdr_fields |= PRR_EDNS::EXT_RCODE_BADCOOKIE & 0b1111;
            // TODO FIXME: we currently always set the RA flag but that really should only be set
            // when we have an upstream DNS server.  (This TODO is also in message.cpp)
            msg.hdr_fields |= flags_QR | flags_RA;
            // badcookie is not an authoritative answer:
            msg.hdr_fields &= ~flags_AA;

            reply(msg.encode(tcp));
            return;
        }

        // If there is no question then there is no answer to worry about.  This is a bit weird, but
        // is sometimes used by clients to get an initial DNS cookie (via EDNS) without making an
        // actual request.
        if (!msg.question)
        {
            reply(msg.encode(tcp));
            return;
        }

        auto& q = *msg.question;

        if (handle_local(reply, msg, std::string{q.name()}, tcp))
            return;

        // we don't provide a DoH resolver because it requires verified TLS TLS needs X509/ASN.1-DER
        // and opting into the Root CA Cabal thankfully mozilla added a backdoor that allows ISPs to
        // turn it off so we disable DoH for firefox using mozilla's ISP backdoor see:
        // https://github.com/oxen-io/lokinet/issues/832

        // is this firefox looking for their backdoor record?
        if (q.name() == "use-application-dns.net")
        {
            // yea it is, let's turn off DoH because god is dead.
            add_nx_soa(msg, "use-application-dns.net", 30s);
            return reply(msg.nxdomain().encode(tcp));  // press F to pay respects and send it back where it came from
        }

        // Not for us, so forward to upstream handler
        forward(std::move(msg), std::move(reply), tcp);
    }

    void RequestHandler::add_nx_soa(Message& m, std::string domain, std::chrono::seconds ttl)
    {
        m.authorities.push_back(std::make_unique<RR_SOA>(
            domain,
            10min /* ttl of the SOA record itself */,
            "localhost.sesh",
            "sr.localhost.sesh",
            _soa_serial++,
            ttl));
    }

    bool RequestHandler::handle_local(ReplyCallback& reply, Message& msg, std::string qname, bool tcp)
    {
        // hook any PTR (reverse DNS) lookups for our local ranges
        if (handle_local_ptr(msg, reply, tcp))
            return true;

        auto& q = *msg.question;

        if (!(q.has_tld(CLIENT_TLD) || q.has_tld(RELAY_TLD) || q.has_tld("loki"sv)))
            return false;

        std::string hostname, tld;
        std::vector<std::string> sub;
        {
            auto nameparts = split(qname, ".");
            if (nameparts.size() < 2)
            {
                log::warning(logcat, "bad DNS request, no TLD or hostname: {}", qname);
                reply(msg.formerr().encode(tcp));
                return true;
            }
            hostname = nameparts[nameparts.size() - 2];
            tld = nameparts.back();
            sub.reserve(nameparts.size() - 2);
            for (auto s : std::views::take(nameparts, static_cast<int>(nameparts.size()) - 2))
                sub.emplace_back(s);
        }

        bool localhost = is_localhost(qname);

        // localhost.sesh/localhost.loki is always a CNAME to our own pubkey, regardless of the
        // question type.
        if (localhost)
        {
            auto our_hostname = _router.id().to_string();
            auto our_tld = _router.is_service_node ? RELAY_TLD : CLIENT_TLD;
            auto our_name = "{}.{}"_format(our_hostname, our_tld);

            if (tld == "loki")
            {
                // first: report a cname for the deprecated localhost.loki -> localhost.sesh

                msg.set_rr_name("localhost.loki");
                msg.add_cname_reply("localhost.{}"_format(our_tld));
            }
            // report CNAME: localhost.sesh -> pubkey.sesh
            msg.set_rr_name("localhost.{}"_format(our_tld));
            msg.add_cname_reply(our_name);

            if (q.qtype == dns::RRType::CNAME)
            {
                // If we were queried specifically for a cname, then we are done.
                reply(msg.encode(tcp));
                return true;
            }

            // Otherwise we continue processing to be able to return supplemental records through
            // the cname, so that if you request "foo.localhost.loki" we end up returning:
            // localhost.loki CNAME for localhost.sesh
            // localhost.sesh CNAME for PUBKEY.sesh
            // foo.PUBKEY.sesh IN X VALUE (or whatever)
            // And so for for the rest of the answer processing that we were given PUBKEY.sesh,
            // rather than localhost.loki/.sesh:
            qname = sub.empty() ? our_name : "{}.{}"_format(fmt::join(sub, "."), our_name);
            msg.set_rr_name(qname);

            tld = our_tld;
            hostname = std::move(our_hostname);
        }
        else if (qname == random_snode)
        {
            // Similar to the localhost case: we first return a CNAME of random.snode ->
            // SOMEPK.snode, then continue processing as if that was what you asked for.

            if (auto* rc = _router.node_db().get_random_rc())
            {
                hostname = rc->router_id().to_string();
                qname = "{}.{}"_format(hostname, RELAY_TLD);
                msg.add_cname_reply(qname, 1s);
                if (q.qtype == dns::RRType::CNAME)
                {
                    reply(msg.encode(tcp));
                    return true;
                }

                msg.set_rr_name(qname);
            }
            else
            {
                // We found no RC at all, which probably means our connection is dead.
                reply(msg.nxdomain().encode(tcp));
                return true;
            }
        }
        else if (tld == "loki" && hostname.size() != oxenc::to_base32z_size(RouterID::SIZE))
        {
            // ONS lookup: initiate a lookup and, when we get the response, set up a CNAME of
            // NAME.loki -> PUBKEY.sesh, then recurse to process other parts of the request (such as
            // mapping to a AAAA).

            // TODO: .sesh SNS resolution, once implemented

            // ONS lookup:
            auto lookup = "{}.loki"_format(hostname);
            _router.session_endpoint().resolve_sns(
                lookup,
                [this,
                 lookup,
                 sub = std::move(sub),
                 reply = std::move(reply),
                 msg_ptr = std::make_shared<dns::Message>(std::move(msg)),
                 cname_only = q.qtype == dns::RRType::CNAME,
                 tcp](
                    std::optional<NetworkAddress> maybe_netaddr,
                    bool assertive,
                    std::chrono::milliseconds ttl) mutable {
                    auto& msg = *msg_ptr;
                    msg.set_rr_name(lookup);
                    if (maybe_netaddr)
                    {
                        auto target = maybe_netaddr->to_string();
                        msg.add_cname_reply(target, std::chrono::floor<std::chrono::seconds>(ttl));
                        if (cname_only)
                            return reply(msg.encode(tcp));
                        auto qname = sub.empty() ? target : "{}.{}"_format(fmt::join(sub, "."), target);
                        msg.set_rr_name(qname);
                        if (!handle_local(reply, msg, std::move(qname), tcp))
                        {
                            log::warning(
                                logcat, "ONS '{}' subrequest did not properly handle sending a reply!", lookup);
                            return reply(msg.servfail().encode(tcp));
                        }
                        return;
                    }

                    if (assertive)
                        add_nx_soa(msg, "loki", std::chrono::floor<std::chrono::seconds>(ttl));

                    reply(msg.nxdomain().encode(tcp));
                });
            return true;
        }

        if (q.qtype == dns::RRType::TXT)
        {
            // TXT records can be used to query some basic info:

            // TXT on MYPUBKEY.sesh returns the basic version and netid:
            if (localhost && sub.empty())
                msg.add_txt_reply("sessionrouter={} v={} netid={}"_format(
                    _router.is_service_node ? "relay" : "client", fmt::join(VERSION, "."), _router.netid()));

            // TXT on PUBKEY.snode gives back some basic RC info (if we have the RC)
            else if (auto rid = is_snode(qname))
            {
                if (auto* rc = _router.node_db().get_rc(*rid))
                {
                    msg.add_txt_reply("rc v={} i={} t={}"_format(
                        fmt::join(rc->version(), "."), rc->addr(), rc->timestamp().time_since_epoch().count()));
                }
                else
                {
                    add_nx_soa(msg, std::string{RELAY_TLD}, 5s);
                    msg.nxdomain();
                }
            }

            // TXT on path.PUBKEY.{sesh,snode} returns the current path info to that node, if a
            // session is established (nxdomain if no active session).
            else if (sub.size() == 1 && sub.front() == "path")
            {
                log::debug(logcat, "TXT path request for {}.{}", hostname, tld);
                if (auto maybe_netaddr = try_making<NetworkAddress>("{}.{}"_format(hostname, tld)))
                {
                    if (auto* s = _router.session_endpoint().get_session(*maybe_netaddr); s && s->is_established())
                    {
                        auto path = s->current_path_info();
                        msg.add_txt_reply(
                            "d={}; path={}; ttl={}; p={}; pj={}.{:03d}; pr={}; pt={}; pT={}"_format(
                                s->is_outbound ? "out" : "in",
                                fmt::join(
                                    std::views::transform(
                                        path.relays, [](const auto& r) { return "{}@{}"_format(r.first, r.second); }),
                                    " "),
                                std::chrono::round<std::chrono::seconds>(path.expiry - srouter::time_now_ms()).count(),
                                path.ping_mean.count(),
                                path.ping_jitter / 1ms,
                                (path.ping_jitter % 1ms).count(),
                                path.ping_responses,
                                path.ping_timeouts,
                                path.ping_recent_timeouts),
                            0s);
                    }
                    else
                        msg.add_txt_reply("d=none");
                }
                else
                {
                    log::warning(logcat, "Failed to parse network address {}.{} for path query", hostname, tld);
                    // If this name was invalid, allow the NXDOMAIN to be cached:
                    add_nx_soa(msg, tld, 30s);
                    msg.nxdomain();
                }
            }
            else
            {
                add_nx_soa(msg, tld, 30s);
                msg.nxdomain();
            }
            reply(msg.encode(tcp));
            return true;
        }

        // "Regular" A or AAAA lookups
        if (bool aaaa = q.qtype == dns::RRType::AAAA; aaaa || q.qtype == dns::RRType::A)
        {
            // Attempt to parse a "pubkey.snode" or "pubkey.sesh":
            if (auto maybe_netaddr = try_making<NetworkAddress>("{}.{}"_format(hostname, tld)))
            {
                // DNS lookup implies we want a session, so make one (NOP if we have one)
                // This also means if we don't use that session the IP mapping will release when
                // it expires, which it wouldn't otherwise without a tedious periodic check.
                bool created_session = false;
                try
                {
                    created_session = (bool)_router.session_endpoint().initiate_remote_session(*maybe_netaddr, nullptr);
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Failed to initiate remote session to {}: {}", *maybe_netaddr, e.what());
                }
                if (created_session)
                {
                    assert(_router.tun_endpoint());
                    auto& tun = *_router.tun_endpoint();
                    if (aaaa)
                        msg.add_reply(tun.map6(*maybe_netaddr));
                    else if (!sub.empty() && sub.back() == "ipv4"sv)
                    {
                        // We don't map IPv4 addresses by default, but it is still possible to get
                        // one by requesting ipv4.somepubkey.sesh/snode (or a subdomain thereof).
                        if (auto v4_addr = tun.map4(*maybe_netaddr); v4_addr)
                            msg.add_reply(*v4_addr);
                        else
                        {
                            // We ran out of local IPv4s, which is a local failure rather than
                            // anything to do with the name, and could succeed later:
                            log::warning(logcat, "IPv4 mapping requested for {} failed.", *maybe_netaddr);
                            msg.servfail();
                        }
                    }
                    else
                    {
                        // They requested A *not* using the magic ipv4 subdomain, so we only have
                        // AAAA to offer and thus we return a reply without an answer record (which
                        // is the proper DNS way to say "something exists at this address, but not
                        // with the type you requested", as opposed to the nxdomain below, which
                        // means "this record does not exist" and would stop a client from going on
                        // to ask for the AAAA that we *can* answer).
                        //
                        // In order for this NODATA result to be properly cacheable, we need an SOA
                        // record included.  It'll also never work in the future, so we can use a
                        // relatively longer negative TTL via the SOA.
                        msg.add_nodata_reply();
                        add_nx_soa(msg, tld, 5min);
                    }
                }
                else
                {
                    // We failed to initiate a sesssion for some reason, which likely means there's
                    // something invalid in what you requested, so make this response authoritative
                    // and cacheable.
                    add_nx_soa(msg, tld, 15s);
                    msg.nxdomain();
                }
                reply(msg.encode(tcp));

                return true;
            }

            log::warning(logcat, "DNS query failure: '{}' is not a valid Session Router name or address", qname);
            add_nx_soa(msg, tld, 30s);
            reply(msg.nxdomain().encode(tcp));
            return true;
        }

        if (q.qtype == dns::RRType::SRV && (tld == CLIENT_TLD || tld == "loki") && sub.size() == 2
            && sub[0].starts_with('_') && sub[1].starts_with('_'))
        {
            if (auto rid = parse_rid(hostname))
            {
                _router.session_endpoint().lookup_client_intro(
                    *rid,
                    [msg = std::make_shared<dns::Message>(std::move(msg)), sub, reply = std::move(reply), tcp](
                        const std::optional<ClientContact>& cc) mutable {
                        if (cc)
                        {
                            bool found = false;
                            for (const auto& srv : cc->SRVs())
                                if (srv.service == sub[0] && srv.proto == sub[1])
                                {
                                    msg->add_reply(srv);
                                    found = true;
                                }

                            // The contact exists, it just doesn't offer the requested
                            // service/proto, which is a NODATA reply rather than a name failure.
                            if (!found)
                                msg->add_nodata_reply();
                        }
                        else
                            // Re-trying the request could initiate a new lookup, so *don't* put an
                            // SOA on this so that the NACK isn't cached.
                            msg->nxdomain();

                        reply(msg->encode(tcp));
                    });
                return true;
            }
        }

        // If we got through everything above without answering then they requested something weird
        // (unhandled RR type, perhaps) and so let's just give an NXDOMAIN back:
        add_nx_soa(msg, tld, 30s);
        reply(msg.nxdomain().encode(tcp));
        return true;
    }

    bool RequestHandler::handle_local_ptr(Message& msg, ReplyCallback& reply, bool tcp)
    {
        assert(msg.question);
        if (msg.question->qtype != srouter::dns::RRType::PTR)
            return false;

        auto ip = dns::decode_ptr(msg.question->qname);
        if (!ip)
            return false;

        auto [mapped, is_ours] = std::visit([this](const auto& ip) { return _router.reverse_lookup(ip); }, *ip);
        if (!is_ours)
            return false;

        if (mapped)
            msg.add_ptr_reply(mapped->to_string());
        else
        {
            // DNS NXDOMAIN records aren't cacheable unless they also have a pseudo-TTL, but there
            // is no direct TTL for does-not-exist: instead it is carried in an SOA record, so make
            // one of those here with a few seconds TTL so that it is (briefly) cacheable, and so
            // that it not currently existing is treated as an authoritative response.

            std::string auth_name;
            if (auto* addr4 = std::get_if<ipv4>(&*ip))
            {
                auto net = _router.tun_endpoint()->get_ipv4_network().to_range();

                // We were asked for A.B.C.D, and so in the SOA we need to indicate what we are
                // authoritative over.  For a /8, /16, or /24 this is easy, just A.in-addr.arpa or
                // B.A.in-addr.arpa or C.B.A.in-addr.arpa but for, say, a /18 this is more
                // complicated: we need to round up the netmask to the next multiple of 8
                // (effectively shrinking the network size) and then return SOA for that.
                //
                // For example, if we are responsible for 10.1.0.0/18 that means 10.1.0.* through
                // 10.1.63.* but not (e.g.) 10.1.65.*, and so we need to "round up" the netmask to
                // /24 and then assert authority over the /24 that included the asked for record.
                // (And so technically we could have 64 different SOA records, but that's okay
                // because we produce them on demand).

                uint8_t mask_up = (std::clamp<uint8_t>(net.mask, 1, 32) + 7) / 8 * 8;
                assert(mask_up % 8 == 0);

                uint32_t soa_addr = (*addr4 / mask_up).ip.addr >> (32 - mask_up);
                for (uint8_t m = mask_up; m > 0; m -= 8)
                {
                    fmt::format_to(std::back_inserter(auth_name), "{}.", soa_addr % 256);
                    soa_addr >>= 8;
                }
                auth_name += ".in-addr.arpa";
            }
            else
            {
                auto& addr6 = std::get<ipv6>(*ip);
                auto net = _router.tun_endpoint()->get_ipv6_network().to_range();

                // Similar to the above, but everything operators on 4-bit hex nybbles rather than 8-bit
                // integers.  e.g.
                // abcd:234::7 is 7.0.0.0........0.4.3.2.0.d.c.b.a
                // and so we have to do the same SOA subdivision (basically our local range netmask
                // might not be a multiple of 4).
                uint8_t mask_up = (std::clamp<uint8_t>(net.mask, 1, 128) + 3) / 4 * 4;
                assert(mask_up % 4 == 0);

                // Rather than calculating this with lots of bit fiddling (complicated by the fact
                // that we need to store the address in two uint64_ts), instead just cheat by using
                // a string representation.  Probably less efficient, but this is not a hot loop
                // path.
                auto soa_base = (addr6 / mask_up).ip;

                // Start with a full, 32-digit raw hex representation of the ipv6 addr (not the
                // usual notation with :, just raw, full width hex digits):
                auto full = fmt::format("{:016x}{:016x}", soa_base.hi, soa_base.lo);

                // chop the netmasked hex digits off the end:
                full.resize(mask_up / 4);

                // now just reverse the remaining hex digits and join with .'s and the suffix:
                auth_name = fmt::format("{}.ip6.arpa", fmt::join(full.rbegin(), full.rend(), "."));
            }

            msg.nxdomain();
            add_nx_soa(msg, std::move(auth_name), 5s);
        }

        reply(msg.encode(tcp));

        return true;
    }

    void RequestHandler::forward(Message&& m, ReplyCallback&& reply, bool tcp)
    {
        if (!_unbound)
        {
            log::warning(
                logcat, "DNS request received for non-Session Router domain, but no upstream DNS is configured!");
            reply(m.refused().encode(tcp));
            return;
        }

        assert(m.question);

        _unbound->query(
            std::string{m.question->name()},
            m.question->qtype,
            m.question->qclass,
            [orig = std::make_shared<Message>(m.clone()), reply = std::move(reply), tcp](
                std::span<const std::byte> response) mutable {
                if (response.empty())
                    return reply(orig->servfail().encode(tcp));

                auto msg = RawMessage::parse(response);
                if (!msg)
                {
                    log::warning(logcat, "Failed to parse unbound query response: {}", buffer_printer{response});
                    return reply(orig->servfail().encode(tcp));
                }

                msg->rewrite_for(*orig);

                reply(msg->encode(tcp));
            });
    }

}  // namespace srouter::dns
