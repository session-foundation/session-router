#include "session.hpp"

#include "constants/path.hpp"
#include "contact/contactdb.hpp"
#include "contact/relay_contact.hpp"
#include "crypto/crypto.hpp"
#include "handlers/tun.hpp"
#include "link/endpoint.hpp"
#include "messages/common.hpp"
#include "nodedb.hpp"
#include "path/path.hpp"
#include "path/transit_hop.hpp"
#include "router/router.hpp"
#include "session/session.hpp"
#include "session/tcp_tunnel.hpp"
#include "util/bspan.hpp"
#include "util/logging/buffer.hpp"
#include "util/random.hpp"
#include "util/time.hpp"
#include "util/try_calling.hpp"

#include <oxen/log/internal.hpp>
#include <oxenc/base32z.h>

#include <chrono>
#include <memory>
#include <random>

namespace srouter::handlers
{
    static auto logcat = log::Cat("session_ep");

    SessionEndpoint::SessionEndpoint(Router& r)
        : path::PathHandler{
              r, r.config().paths.inbound_paths + r.config().paths.inbound_paths_extra, r.config().paths.inbound_hops()}
    {
        if (!r.is_service_node)
        {
            const auto& netconf = router.config().network;

            _auth_tokens = netconf.exit_auths;

            protocol_flag protocols = protocol_flag::PFS_PQ;
            if (!router.embedded())
                protocols |= protocol_flag::IPV4 | protocol_flag::IPV6 | protocol_flag::TCP_TUNNEL;

            client_contact.emplace(
                router.key_manager.router_id(), netconf.srv_records, protocols, sys_ms{}, netconf.traffic_policy);

            cc_blind_keys.emplace(r.secret_key(), crypto::blinding::CLIENT_CONTACT);
        }
    }

    std::array<int, 5> SessionEndpoint::session_stats() const
    {
        std::array<int, 5> stats{0};
        auto& [in, out_r, out_c, out_r_pending, out_c_pending] = stats;

        for (const auto& s : std::views::values(_sessions))
        {
            if (s->is_closed())
                continue;
            if (s->is_outbound)
            {
                if (s->is_relay_session)
                {
                    out_r++;
                    if (!s->is_established())
                        out_r_pending++;
                }
                else
                {
                    out_c++;
                    if (!s->is_established())
                        out_c_pending++;
                }
            }
            else
                in++;
        }

        return stats;
    }

    std::array<int, 3> SessionEndpoint::path_stats(sys_ms now) const
    {
        std::array<int, 3> stats{0};
        auto& [in, out_r, out_c] = stats;
        in = num_paths();

        for (const auto& s : std::views::values(_sessions))
            if (!s->is_closed() && s->is_outbound)
            {
                auto& os = static_cast<const session::OutboundSession&>(*s);
                if (os.is_relay_session)
                    out_r += os.num_paths(now);
                else
                    out_c += os.num_paths(now);
            }

        return stats;
    }

    void SessionEndpoint::close_session(const std::shared_ptr<session::Session>& s, bool send_close)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (!s)
            return;

        s->close(send_close);

        const auto& remote = s->remote();
        if (auto& tun = router.tun_endpoint())
            tun->expire(remote);

        // defer this in case we're in the middle of iterating the container(s)
        // capture a weak_ptr to the session so that if for whatever reason
        router._jq->call_soon([this, weak = std::weak_ptr(s)]() {
            if (auto shared = weak.lock())
            {
                if (auto it = _sessions.find(shared->remote()); it != _sessions.end())
                {
                    if (shared != it->second)
                        return;  // session is already gone

                    if (auto& s = it->second)
                        _session_tags.erase(s->inbound_tag());
                    _sessions.erase(it);
                }
            }
        });
    }

    bool SessionEndpoint::close_session(NetworkAddress remote, bool send_close)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (auto it = _sessions.find(remote); it != _sessions.end())
        {
            close_session(it->second, send_close);
            return true;
        }

        log::warning(logcat, "Could not find session (remote:{}) to close!", remote);
        return false;
    }

    bool SessionEndpoint::close_session(session_tag t, bool send_close)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (auto it = _session_tags.find(t); it != _session_tags.end())
        {
            close_session(it->second, send_close);
            return true;
        }

        log::warning(logcat, "Could not find session (tag:{}) to close!", t);
        return false;
    }

    void SessionEndpoint::tick(sys_ms now)
    {
        log::trace(logcat, "SessionEndpoint ticking sessions...");
        for (const auto& [addr, session] : _sessions)
            session->tick(now);

        path::PathHandler::tick(now);
    }

    void SessionEndpoint::stop(bool send_close)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        _running = false;

        if (_path_rotater)
        {
            _path_rotater.reset();
            log::trace(logcat, "Path rotation ticker stopped!");
        }

        // Do a best-effort close; if send_close is true these close(true) calls should queue a
        // path_close on the active stream, even though we immediately drop the streams below, which
        // should still typically arrive at the other side.
        for (auto& s : std::views::values(_sessions))
            s->close(send_close);

        // Note: we intentionally do NOT clear _sessions here.  Session objects (which are also
        // PathHandlers) may still be referenced by pending QUIC stream callbacks (e.g. path build
        // timeouts) that fire asynchronously after this stop() call returns.  Clearing the sessions
        // here would free those PathHandler objects while their callbacks are still queued, leading
        // to use-after-free.  Instead, we let _sessions be cleaned up naturally when this
        // SessionEndpoint is destroyed (which happens during `delete router`, after all such
        // callbacks have been drained from the event loop).
        _session_tags.clear();

        path::PathHandler::stop();
    }

    void SessionEndpoint::cleanup_old_fuzz(int oldest_slot)
    {
        if (auto it = _slot_fuzz.lower_bound(oldest_slot); it != _slot_fuzz.end() && it != _slot_fuzz.begin())
            _slot_fuzz.erase(_slot_fuzz.begin(), it);
    }

    std::chrono::seconds SessionEndpoint::inbound_path_fuzz(int slot)
    {
        auto it = _slot_fuzz.lower_bound(slot);
        if (it != _slot_fuzz.end() && it->first == slot)
            return it->second;

        // Note that this fuzz must not be negative!  If we allowed negative fuzz then a path could
        // expire *before* its slot expired, and as a result we would try to build a new very short
        // path to make up for the expired slot.
        std::normal_distribution<float> dist{0, path::MAX_LIFETIME_FUZZ.count() / 2.575829f};
        std::chrono::seconds fuzz;
        do
        {
            fuzz = std::chrono::seconds{static_cast<int>(dist(csrng))};
            if (fuzz < 0s)
                fuzz = -fuzz;
        } while (fuzz > path::MAX_LIFETIME_FUZZ);

        _slot_fuzz.emplace_hint(it, slot, fuzz);

        return fuzz;
    }

    void SessionEndpoint::update_paths(sys_ms now)
    {
        int have = num_paths(now);
        // If you ask for more than 10 inbound paths (which is only possible via an undocumented
        // option) and more than the number of RCs we know about then silently cut off at the number
        // of RCs we know about (or a multiple of those, if pivot reuse is allowed) to avoid seeing
        // a warning about not being able to select new pivots every 250ms.
        int max_paths = router.node_db().num_rcs() * router.config().paths.inbound_pivot_reuse;
        int needed = (_target_paths > 10 && _target_paths > max_paths ? max_paths : _target_paths) - have;
        if (needed <= 0)
        {
            log::trace(
                logcat,
                "SessionEndpoint doesn't need more paths right now (have {} >= target {})",
                have,
                _target_paths);
            return;
        }

        if (cooldown())
        {
            log::debug(
                logcat,
                "SessionEndpoint needs {} more paths (to reach target {}), but path builds are currently in cooldown "
                "because the last {} path builds failed",
                needed,
                _target_paths,
                _consecutive_failures);
            return;
        }

        log::debug(
            logcat,
            "SessionEndpoint building {} additional paths to random remotes to reach target of {} paths",
            needed,
            _target_paths);

        // If we *don't* have distinct IP ranges from our current edges (e.g. by random chance, or
        // with only a single edge, or just because that's how the pinned edges pan out) then we
        // want to exclude the random terminus that we choose to exclude that singleton range from
        // being the terminus: because otherwise we can end up in a situation where it is impossible
        // to respect the distinct-ip-range setting because once we have selected a pivot, and feed
        // it into PathHandler::select_hops_to_remote, it has no choice but to use that pivot *and*
        // the edge, and those conflict.
        //
        // (If we have multiple ranges for edges then it's not an issue because whichever pivot we
        // select will have at least one available edge not in its range).
        //
        // So, if we're in that only-one-edge-ip-range case, we apply the edge exclusion back here at
        // terminus selection so that our selection here doesn't force select_hops_to_remote into
        // that situation.

        auto unique_edge_range = router.link_endpoint().unique_edge_range();

        auto filter = [this, &unique_edge_range](const RelayContact& rc) {
            if (unique_edge_range and unique_edge_range->contains(rc.addr().to_ipv4()))
                return false;

            // Exclude any inbound pivots we are already using (or using more than
            // inbound_pivot_reuse times, if that option is higher than 1) so that we diversify:
            int count = 0;
            const auto& rid = rc.router_id();
            for (const auto& p : paths())
                if (p.terminal_rid() == rid)
                    if (++count >= router.config().paths.inbound_pivot_reuse)
                        return false;

            return not router.router_profiling().is_bad_for_path(rid, 1);
        };

        // Path lifetime selection
        // -----------------------
        //
        // We want our CC path expiries to be spread out temporally because if we have them
        // clustered together, we can end up in a situation where all our inbound paths expire at
        // the same time, and so someone connected to us cannot stay connected, because they have
        // no other paths to rotate to.
        //
        // To solve this, we try to ensure that paths are always spread out across expiries.  For
        // example, with 4 target inbound paths, we ideally want paths that expire at
        //
        // [P1: t₀+5min, P2: t₀+10min, P3: t₀+15min, P4: t₀+20min]
        //
        // and when we reach t₁ = t₀+5min, the first expires, and we build a new one for t₁+20min
        // (== t₀ + 25min), thus ending up with:
        //
        // [P2: t₁+5min, P3: t₁+10min, P4: t₁+15min, P5: t₁+20min]
        //
        // and so on over time.
        //
        // The problem, however, is that paths can die.  Suppose, for instance, that P4 dies at
        // t₂ = t₁+1min.  That means just before processing the path death we have:
        //
        // [P2: t₂+4min, P3: t₂+9min, P4: t₂+14min, P5: t₂+19min]
        //
        // and then after processing we have:
        //
        // [P2: t₂+4min, P3: t₂+9min, P5: t₂+19min]
        //
        // If we construct a new, full-lifetime path at this point we'll have:
        //
        // [P2: t₂+4min, P3: t₂+9min, P5: t₂+19min, P6: t₂+20min]
        //
        // which is okay for now, but will lead to us having a perpetual 1min gap between P5 and P6
        // (and then also between the P9 and P10 replacements when P5/6 expire), and a 9min gap
        // between P4/P5 (and between its replacements).
        //
        // Worse, if all your paths die at once (for instance, because your local internet died
        // temporarily) you would rebuild all 4 paths at once, and could end up with all expiring at
        // the same time.
        //
        // So it isn't enough to just spread them out initially: we have to create new paths with a
        // lifetime that slots them into the expiry time the path they are replacing would have had.
        // E.g. rather than the above lumpy distribution, we want the paths with P6 to look like:
        //
        // [P2: t₂+4min, P3: t₂+9min, P6: t₂+14min, P5: t₂+19min]
        //
        // so that "re-slotting" the path with the earlier timestamp keeps the distribution nice and
        // spread out, preventing unwanted clustering of expiries.
        //
        // For 2 or 3 paths, we space things out proportionally, e.g.:
        //
        // 2: [P1: t+10m, P2: t+20m]
        // 3: [P1: t+6m40s, P2: t+13m20s, P3: t+20m]
        //
        // Beyond 4, we use the same 5m spacing as with 4, but double up some slots.  For example,
        // with 7 paths:
        //
        // 7: [P1: t+5m, P2&P5: t+10m, P3&P6: t+15m, P4&P7: t+20m]
        //
        // This is somewhat lopsided for non-multiples of 4, but there's still lots of spread in
        // there so that even with multiple paths expiring at the same time, there are still lots of
        // alternatives for remotes to switch to.
        //
        // Note that all of the above ignores "fuzz", i.e. each path has a small random amount of
        // lifetime (well less than 5min) added to it to reduce the fingerprintability of path build
        // expiries.  All of the above still holds with respect to slots, it's just that where we
        // write "+Nm" it's actually "+Nm+fuzz[0,3m]".

        std::vector<std::chrono::sys_seconds> expiries;
        expiries.reserve(needed);
        {
            const int slots = std::min(_target_paths, path::MAX_LIFETIME_SLOTS);

            // Our expiry slot size.  Generally 5min, but longer if you use fewer than 4 paths:
            const std::chrono::seconds slot_size = path::MAX_LIFETIME / slots;
            assert(path::MAX_LIFETIME % slots == 0s);

            std::array<int, path::MAX_LIFETIME_SLOTS> slot_count = {0};

            // The base slot, measured in multiples of `slot_size` relative to our fixed basis: we
            // consider other path expiries relative to this base slot.
            //
            // The +1 here is because (now-basis)/slot_size (i.e. without the +1) is going to give
            // us a slot index that translates to a slot start time in the past (i.e. 0-5min ago),
            // but we don't build for that slot: instead we build for slots at +5m, +10m, +15m, +20m
            // from that now-or-earlier point.  Thus +1 brings us up to the first slot position
            // within the next [0-5min], and that is our "slot0" value, i.e. the index 0 slot of all
            // slots we consider building for.
            //
            // There is an argument to be made to not build new paths that would only have a
            // duration of 0-5 min, but for now it's much simpler and cleaner to just build those
            // paths anyway (if no path in that slot).
            int slot0 =
                static_cast<int>((std::chrono::floor<std::chrono::seconds>(now) - path_expiry_basis) / slot_size + 1);

            // First count up all the slots we are already using with existing paths:
            int path_count = 0;
            for (auto& path : paths())
            {
                path_count++;
                // Path expiries will be up to +MAX_LIFETIME_FUZZ of their slot target expiry time, so we need
                // to be sure that the maximum fuzz is less then the smallest possible slot size so
                // that it is guaranteed to be counted in the same slot:
                static_assert(
                    path::MAX_LIFETIME_FUZZ < path::MAX_LIFETIME / path::MAX_LIFETIME_SLOTS,
                    "The slot calculation below requires path max fuzz be strictly smaller than the smallest allowed "
                    "path slot size!");
                auto slot = (path.expiry() - path_expiry_basis) / slot_size;
                if (slot < slot0)
                {
                    log::debug(logcat, "Ignoring expired/expiring path slot {}", slot);
                    continue;  // Path is expired/expiring, so ignore it.
                }
                slot -= slot0;
                if (slot >= slots)
                {
                    log::warning(logcat, "Found inbound path with unexpected future expiry, this should not happen!");
                    continue;
                }
                slot_count[slot]++;
            }

            log::trace(
                logcat, "Current {} path expiry slots (oldest-newest): {}", path_count, fmt::join(slot_count, "-"));

            // We want all paths built in a given slot to expire at the same time so that we publish
            // CCs on average once every 5 minutes, even if we are using many paths, and so we reuse
            // the same fuzz value for any paths built in the same slot (whether in this build or a
            // previous one that we are rebuilding for here).
            cleanup_old_fuzz(slot0);

            // Now we select new ones by looking for the slot with the fewest paths in it, preferring
            // later slots (i.e. longer expiries) in case of a tie, and keep repeating this for
            // however many paths we need:
            for (int i = 0; i < needed; i++)
            {
                int best = 0;
                for (int j = 1; j < slots; j++)
                    if (slot_count[j] <= slot_count[best])
                        best = j;
                const auto slot = slot0 + best;
                expiries.emplace_back(path_expiry_basis + slot * slot_size + inbound_path_fuzz(slot));
                slot_count[best]++;
            }

            log::trace(logcat, "Select new path expiries: {}", fmt::join(expiries, ", "));
        }

        auto next_expiry = expiries.begin();

        if (num_hops() == 1)
        {
            // In single-hop mode the edge and pivot are the same thing, and so we need to select
            // the edge (according to various configured edge selection rules), because if we
            // selected a random pivot first we'd bypass all the edge rules (pinned edges,
            // relay-connections, and so on).
            for (; needed > 0; needed--)
            {
                auto only_hop = select_first_hop();
                if (!only_hop)
                {
                    log::warning(logcat, "Unable to build a new inbound single-hop path: no eligible edges");
                    return;
                }
                build(std::span{&*only_hop, 1}, *next_expiry++);
            }
        }
        else
        {
            // We can potentially multi-pass through this because it can only return at most # of
            // RCs, but pivot reuse might mean that we need to build paths using some RCs more than
            // once.  (This is probably mostly a testnet concern).
            int built = 0;
            do
            {
                auto new_pivots = router.node_db().get_n_random_rcs(needed, true, filter);
                if (new_pivots.empty())
                    break;
                needed -= static_cast<int>(new_pivots.size());
                for (const srouter::RelayContact* rc : new_pivots)
                {
                    log::debug(logcat, "Selected new inbound path terminus {}", rc->router_id().short_string());
                    auto hops = select_hops_to_remote(rc->router_id());
                    if (!hops)
                        continue;  // No need to warn: the call above should already if it fails

                    build(*hops, *next_expiry++);
                    built++;
                }
            } while (needed > 0);

            if (needed > 0)
                log::warning(
                    logcat,
                    "Failed to build {} of {} new inbound paths: ran out of available unused/acceptable pivots",
                    needed,
                    needed + built);
        }
    }

    void SessionEndpoint::on_path_build_success(int64_t /*build_id*/, path::Path& p)
    {
        log::debug(logcat, "Successfully built path {}", p);

        router.on_inbound_path_change(true);

        if (not router.config().network.is_reachable)
            return;

        // else we publish an introset, so check if we need to publish it now.

        // We just built a new path: if that path brings our active paths to the target number of
        // paths then we want to publish the introset.  *Typically* this will just end up on a
        // regular timer (i.e. paths expire naturally, we rebuild them, and once all expired ones
        // are rebuilt we end up here to republish), but in case of premature path death we might
        // also end up here (and also need to republish so that clients in the wild don't try
        // aligning to the dead path).

        if (num_active_paths() < _target_paths)
            return;  // We haven't met our target yet (or they are still building), so wait for them
                     // to finish rebuilding before we publish.

        log::info(logcat, "Inbound active paths changed; re-publishing client contact");
        update_and_publish_localcc();
    }

    void SessionEndpoint::no_established_paths_left() { router.on_inbound_path_change(false); }

    void SessionEndpoint::on_path_build_failure(int64_t /*build_id*/, path::Path* path, bool timeout)
    {
        if (path)
            log::warning(logcat, "Path build for {} {}", *path, timeout ? "timed out" : "failed");
        else
            log::warning(logcat, "Path build failed: cannot construct a new path right now");
    }

    void SessionEndpoint::resolve_sns_mappings()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);
        auto& sns_ranges = router.config().exit.sns_ranges;

        if (not sns_ranges.empty())
        {
            log::debug(logcat, "SessionEndpoint resolving {} SNS addresses mapped to IP ranges", sns_ranges.size());

            for (const auto& [name, ip_range] : sns_ranges)
            {
                resolve_sns(
                    name,
                    [this, ip_range](
                        std::optional<NetworkAddress> maybe_addr, bool assertive, std::chrono::milliseconds /*ttl*/) {
                        if (maybe_addr)
                        {
                            log::critical(
                                logcat,
                                "UNIMPLEMENTED: Successfully resolved SNS lookup for {} mapped to IPRange:{}",
                                *maybe_addr,
                                ip_range);
                            // TODO FIXME: we need to sort out how these addresses get actually
                            // mapped.
                            //_range_map.insert_or_assign(std::move(ip_range), std::move(*maybe_addr));
                        }
                        // we don't need to print a fail message, as it is logged prior to invoking with std::nullopt
                    });
            }
        }

        auto& sns_auths = router.config().network.sns_exit_auths;

        if (auto n_sns_auths = sns_auths.size(); n_sns_auths > 0)
        {
            log::debug(logcat, "SessionEndpoint resolving {} ONS addresses mapped to auth tokens", n_sns_auths);

            for (const auto& [name, auth_token] : sns_auths)
            {
                resolve_sns(
                    name,
                    [this, auth_token](
                        std::optional<NetworkAddress> maybe_addr, bool assertive, std::chrono::milliseconds /*ttl*/) {
                        if (maybe_addr)
                        {
                            log::debug(
                                logcat,
                                "Successfully resolved SNS lookup for {} mapped to static auth token",
                                *maybe_addr);
                            _auth_tokens.emplace(std::move(*maybe_addr), std::move(auth_token));
                        }
                        // we don't need to print a fail message, as it is logged prior to invoking with std::nullopt
                    });
            }
        }
    }

    void SessionEndpoint::resolve_sns(
        std::string sns,
        std::function<void(std::optional<NetworkAddress>, bool assertive, std::chrono::milliseconds ttl)> func)
    {
        Lock_t l{paths_mutex};
        if (not is_valid_sns(sns))
        {
            log::warning(logcat, "Invalid SNS name ({}) queried for lookup", sns);
            try_calling(logcat, func, std::nullopt, true, 0ms);
            return;
        }

        log::debug(logcat, "Looking up SNS name {}", sns);

        if (auto it = _sns_cache.find(sns); it != _sns_cache.end())
        {
            auto& [addr, expiry] = it->second;
            auto now = time_now_ms();
            if (expiry > now)
            {
                if (addr)
                    log::debug(logcat, "Found SNS entry in cache: {} -> {}", sns, *addr);
                else
                    log::debug(logcat, "Found SNS does-not-exist entry in cache for {}", sns);
                try_calling(logcat, func, addr, true, expiry - now);
                return;
            }

            // Else it's expired, so erase it.  (We don't worry about cleaning it periodically; a
            // few stale entries sitting around until the next time we try to look them up won't
            // hurt anything).
            _sns_cache.erase(it);
        }

        struct sns_results_t
        {
            // We send the request to multiple nodes, and then confirm responses:
            // - if we get at least half of the responses that agree (same address, or all say not
            //   found) then we return that result.
            // - otherwise (i.e. if we reach the end of responses without getting a 50%+ winning
            //   result) then we return the most popular: In the case of ties, if "not found" is one
            //   of the tied values, we return not found; otherwise we randomize among any with the
            //   same number of confirmations.
            std::unordered_map<NetworkAddress, int> result_count;
            int not_found_count = 0;
            int remaining = 0;
            int threshold = 0;
            std::string name;
        };
        auto sns_results = std::make_shared<sns_results_t>();
        sns_results->name = sns;

        auto response_handler = [this, sns_results, func = std::move(func)](path::path_control_response resp) {
            if (--sns_results->remaining < 0)
                return;  // Already processed and sent the response

            const auto& name = sns_results->name;
            if (resp.ok())
            {
                try
                {
                    log::debug(logcat, "Call to ResolveSNS succeeded!");

                    oxenc::bt_dict_consumer sns{resp.body};
                    if (auto err = sns.maybe<std::string_view>(messages::STATUS_KEY);
                        err && *err != messages::STATUS_OK)
                    {
                        if (*err == messages::STATUS_NOT_FOUND)
                        {
                            log::debug(logcat, "Relay returned CC not found");
                            sns_results->not_found_count++;
                        }
                        else
                        {
                            throw std::runtime_error{"Relay returned unknown status {}"_format(*err)};
                        }
                    }
                    else
                    {
                        auto ciphertext = sns.require<std::string_view>("c");
                        SymmNonce nonce{sns.require_span<std::byte, SymmNonce::SIZE>("n")};
                        sns.finish();

                        if (auto addr = crypto::maybe_decrypt_name(ciphertext, nonce, name))
                        {
                            log::debug(logcat, "Successfully decrypted SNS response {} -> {}", name, *addr);

                            ++sns_results->result_count[*addr];
                        }
                        else
                            log::warning(logcat, "Failed to decrypt SNS record (name: {})", name);
                    }

                    // See if we have a two-response confirmation with no dissent, and if so return
                    // early:
                    if (sns_results->not_found_count >= sns_results->threshold)
                    {
                        log::debug(logcat, "SNS result: {} not found ({} confs)", name, sns_results->not_found_count);
                        _sns_cache[name] = {std::nullopt, time_now_ms() + SNS_CACHE_TIME};
                        try_calling(logcat, func, std::nullopt, true, SNS_CACHE_TIME);
                        sns_results->remaining = 0;
                        return;
                    }
                    for (const auto& [addr, count] : sns_results->result_count)
                    {
                        if (count >= sns_results->threshold)
                        {
                            log::debug(logcat, "SNS result: {} -> {} ({} confs)", name, addr, count);
                            _sns_cache[name] = {addr, time_now_ms() + SNS_CACHE_TIME};
                            try_calling(logcat, func, addr, true, SNS_CACHE_TIME);
                            sns_results->remaining = 0;
                            return;
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Exception during SNS response handling for {}: {}", name, e.what());
                }
            }

            if (sns_results->remaining == 0)
            {
                // We are the last response handler, and we didn't exit via the above threshold
                // confirmation offramps, so we need to pick a winner based on whatever results we
                // got:
                if (sns_results->result_count.empty())
                {
                    // No resolved results; return DNE, authoritatively if we saw at least one not found response:
                    bool assertive = sns_results->not_found_count > 0;
                    if (assertive)
                        _sns_cache[name] = {std::nullopt, time_now_ms() + SNS_CACHE_TIME};
                    try_calling(logcat, func, std::nullopt, assertive, assertive ? SNS_CACHE_TIME : 0ms);
                }
                else
                {
                    std::vector<NetworkAddress> best;
                    int best_count = 0;
                    for (auto& [addr, count] : sns_results->result_count)
                    {
                        if (count >= best_count)
                        {
                            if (count > best_count)
                            {
                                best_count = count;
                                best.clear();
                            }
                            best.push_back(addr);
                        }
                    }
                    if (sns_results->not_found_count >= best_count)
                    {
                        // If "does not exist" has at least as many results as the best "found"
                        // result, return DNE:
                        _sns_cache[name] = {std::nullopt, time_now_ms() + SNS_CACHE_TIME};
                        try_calling(logcat, func, std::nullopt, true, SNS_CACHE_TIME);
                    }
                    else
                    {
                        // If we have one single best, send it; if tied, randomize:
                        size_t i = 0;
                        if (best.size() > 1)
                            i = std::uniform_int_distribution<size_t>{0, best.size() - 1}(csrng);
                        _sns_cache[name] = {best[i], time_now_ms() + SNS_CACHE_TIME};
                        try_calling(logcat, func, best[i], true, SNS_CACHE_TIME);
                    }
                }
            }
        };

        auto name_hash = crypto::shorthash(as_bspan(sns));

        // We fire this request down at most 5 utility paths so that if you've configured lots of
        // paths, we don't spam them all for every ONS lookup.
        for (auto& path : active_paths())
        {
            ++sns_results->remaining;
            log::debug(
                logcat, "Querying pivot:{} for name lookup (target: {})", path.terminal_rid().short_string(), sns);
            path.resolve_sns(name_hash, response_handler);

            if (sns_results->remaining >= 5)
                break;
        }
        sns_results->threshold = (sns_results->remaining + 1) / 2;

        if (sns_results->remaining == 0)
        {
            log::warning(logcat, "Unable to resolve SNS name {}: we have no active paths", sns);
            // Since we didn't make any actual requests, construct a fake response so that we can go
            // through the lambda above (which we moved `func` into!) for response processing as if
            // we got a single error response
            sns_results->remaining = 1;
            path::path_control_response fake_resp{};
            fake_resp.error = true;
            response_handler(std::move(fake_resp));
        }
    }

    void SessionEndpoint::lookup_relay_contact(RouterID remote, std::function<void(std::optional<RelayContact>)> func)
    {
        router.node_db().lookup_rc(remote, std::move(func));
    }

    const std::optional<ClientContact>& SessionEndpoint::update_cc(
        const RouterID& remote, std::optional<ClientContact>&& cc)
    {
        auto new_exp = cc ? cc->expiry() : time_now_ms() + NO_CC_CACHE_TIME;
        auto [it, new_entry] = _cc_cache.try_emplace(remote, std::move(cc), new_exp);
        if (new_entry)
        {
            log::debug(logcat, "New CC stored for {}.{}", remote, CLIENT_TLD);
            return it->second.first;
        }

        // Otherwise the cache already had an entry, so we need to figure out whether the new value
        // is better than the old one:
        // - if the old entry is expired, use the new one.
        // - if the existing cache entry is nullopt, then prefer the new one.
        // - if the existing cache entry is set but new is nullopt, leave the existing one.
        // - if both are set then prefer the one with the later signed-at timestamp.

        auto& [entry, exp] = it->second;
        auto now = time_now_ms();
        if (!entry || exp < now || (cc && cc->signed_at() > entry->signed_at()))
        {
            bool was_null = !entry;
            entry = std::move(cc);
            exp = new_exp;
            log::debug(logcat, "{} for {}.{}", was_null ? "New CC stored" : "Updated CC", remote, CLIENT_TLD);
        }
        else
        {
            log::debug(
                logcat,
                "Ignoring CC received for {}.{}: current cached value is the same or newer",
                remote,
                CLIENT_TLD);
        }
        return entry;
    }

    void SessionEndpoint::lookup_client_intro(
        RouterID remote, std::function<void(const std::optional<ClientContact>&)> func, bool allow_cache)
    {
        if (remote == router.id())
        {
            log::debug(logcat, "lookup intro for ourself: returning stored CC");
            try_calling(logcat, func, client_contact);
            return;
        }

        if (allow_cache)
        {
            if (auto it = _cc_cache.find(remote); it != _cc_cache.end())
            {
                const auto& [cc, exp] = it->second;
                auto now = time_now_ms();
                if (exp <= now)
                    _cc_cache.erase(it);
                else
                {
                    log::debug(logcat, "Found cached CC for remote {}", remote.to_network_address(false));
                    try_calling(logcat, func, cc);
                    return;
                }
            }
        }

        PubKey remote_key;
        if (!crypto::blind(remote_key, remote, crypto::blinding::CLIENT_CONTACT))
        {
            log::warning(
                logcat,
                "Failed to blind remote address {}: this is most likely not a valid address",
                remote.to_network_address(false));
            try_calling(logcat, func, update_cc(remote, std::nullopt));
            return;
        }

        log::debug(
            logcat,
            "Initiate network ClientContact lookup (blinded key: {}) for {}",
            remote_key,
            remote.to_network_address(false));

        // Will be set to 0 once we have seen an successful response, and so later responses will
        // set a negative (after decrementing).  If a response callback sees 0 that means that it is
        // responsible for sending an error (i.e. this implies all requests failed).
        auto remaining = std::make_shared<int>(0);

        auto response_handler = [remote, func, remaining, this](auto resp) {
            int rem = --*remaining;

            std::optional<ClientContact> cc;
            try
            {
                if (resp.ok())
                {
                    oxenc::bt_dict_consumer cc_dict{resp.body};
                    bool failed = false;
                    if (auto err = cc_dict.maybe<std::string_view>(messages::STATUS_KEY);
                        err && *err != messages::STATUS_OK)
                    {
                        failed = true;
                        if (*err == messages::STATUS_NOT_FOUND)
                        {
                            log::debug(logcat, "Relay returned CC not found");
                        }
                        else
                        {
                            throw std::runtime_error{"Relay returned unknown status {}"_format(*err)};
                        }
                    }
                    if (!failed)
                    {
                        log::debug(logcat, "Call to FindClientContact succeeded!");
                        cc = ClientContact::decrypt(cc_dict.require_span<std::byte>("x"), remote);
                    }
                }
                else
                {
                    oxenc::bt_dict_consumer btdc{resp.body};
                    auto status = btdc.maybe<std::string>(messages::STATUS_KEY);

                    log::warning(
                        logcat, "Call to FindClientContact FAILED; reason: {}", status.value_or("<none given>"));
                }
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Failed to load client contact: {}", e.what());
            }

            if (cc)
            {
                // Offer it to the cache whether or not e need to call the callback so that if one
                // of the later callbacks return a better value, we keep that better value on hand.
                auto& ccc = update_cc(remote, std::move(cc));

                if (rem > 0)
                    *remaining = 0;
                if (rem >= 0)
                    try_calling(logcat, func, ccc);
            }
            else if (rem == 0)
            {
                // Last chance and all failed, so trigger failure
                try_calling(logcat, func, update_cc(remote, std::nullopt));
            }
        };

        Lock_t l{paths_mutex};

        // We submit 4 CC fetches down 4 paths (reusing paths if we have less than 4), each
        // requesting a specific network storage index.  When the first response comes back, we use
        // it; but if we get others after that that are better (i.e. newer) then we update when they
        // arrive as well.
        //
        // Doing this provides some redundancy on lookup: even if the requested CC storage "missed"
        // some nodes (and perhaps left stale ones behind), we should still have a reasonable chance
        // to get the latest one even if a server with a stale one happens to respond faster to all
        // the relay endpoints of our utility path.
        std::vector<path::Path*> paths;
        paths.reserve(4);
        for (auto& p : active_paths())
        {
            paths.push_back(&p);
            if (paths.size() >= 4)
                break;
        }
        if (!paths.empty())
        {
            for (int lookup_idx = 0; lookup_idx < 4; lookup_idx++)
            {
                auto& path = *paths[lookup_idx % paths.size()];
                ++*remaining;

                log::debug(
                    logcat,
                    "Querying pivot (rid:{}) for ClientContact lookup target (rid:{})",
                    path.terminal_rid().short_string(),
                    remote);

                path.find_client_contact(remote_key, lookup_idx, response_handler);
            }
        }
        else
        {
            log::warning(logcat, "CC lookup failed: no usable paths!");
            // Don't cache this nullopt: we didn't even attempt a lookup, and an immediate
            // subsequent call to this function will either end up right back here (with nothing
            // sent), or will send it.
            try_calling(logcat, func, std::nullopt);
        }
    }

    void SessionEndpoint::update_and_publish_localcc()
    {
        if (!router.config().network.is_reachable)
        {
            log::debug(logcat, "Not publishing CC: publishing is disabled by config");
            return;
        }

        assert(client_contact && cc_blind_keys);

        log::debug(logcat, "Updating and publishing ClientContact...");

        auto now = srouter::time_now_ms();
        std::vector<ClientIntro> intros;
        for (const auto& [hopid, p] : _paths)
            if (p and p->is_active(now))
                intros.push_back(p->make_intro());

        client_contact->update_intros(std::move(intros));

        log::debug(logcat, "New ClientContact: {}", *client_contact);
#ifndef NDEBUG
        log::debug(logcat, "ClientContact details:");
        log::debug(logcat, "Pubkey: {}", client_contact->pubkey());
        log::debug(logcat, "{} SRV records", client_contact->SRVs().size());
        log::debug(logcat, "Intros ({}):", client_contact->intros().size());
        for (const auto& ci : client_contact->intros())
            log::debug(
                logcat,
                "    • {}, hopid: {}, expiry: {}",
                ci.relay.to_network_address(),
                ci.hop,
                std::chrono::floor<std::chrono::seconds>(ci.expires_in(now)));
#endif

        try
        {
            publish_client_contact(client_contact->encrypt_and_sign(*cc_blind_keys));
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "ClientContact encryption/signing exception: {}", e.what());
        }
    }

    bool SessionEndpoint::validate(const NetworkAddress& remote, std::optional<std::string> maybe_auth)
    {
        auto& netconf = router.config().network;
        auto& tokens = netconf.auth_static_tokens;
        auto& whitelist = netconf.auth_whitelist;
        if (tokens.empty() && whitelist.empty())
            return true;  // No auth required

        if (maybe_auth && tokens.contains(*maybe_auth))
            return true;  // valid auth token

        if (whitelist.contains(remote))
            return true;  // valid address

        return false;
    }

    std::optional<ipv4> SessionEndpoint::map_session_v4(const session::Session& s)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (const auto& tun = router.tun_endpoint())
        {
            log::debug(logcat, "Mapping local tun ipv4 for inbound session from {}", s.remote());
            auto addr = tun->map4(s.remote());
            if (addr)
                log::debug(logcat, "Mapping successful, address: {}", *addr);
            else
                log::warning(logcat, "Mapping unsuccessful; out of available addresses?");
            return addr;
        }

        // TODO: no tun-based

        return std::nullopt;
    }

    std::optional<ipv6> SessionEndpoint::map_session_v6(const session::Session& s)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (const auto& tun = router.tun_endpoint())
        {
            log::debug(logcat, "Successfully mapped inbound session; mapping session to local TUN IPv6");

            // TODO: this can throw if you have a tiny IPv6 range; we should catch that and close
            // the session.
            auto addr = tun->map6(s.remote());
            log::info(logcat, "TUN device successfully mapped session (remote: {}) to local ip: {}", s.remote(), addr);
            return addr;
        }

        // TODO: if we're not tun-based -- currently not allowing inbound sessions for non-tun

        return std::nullopt;
    }

    void SessionEndpoint::handle_session_init(std::span<const std::byte> payload, std::shared_ptr<path::Path> path)
    {
        std::shared_ptr<session::InboundSession> new_session{};
        try
        {
            new_session = std::make_shared<session::InboundClientSession>(*this, std::move(path), std::move(payload));
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Inbound session rejected: {}", e.what());
            return;
        }
        session_post_init(std::move(new_session));
    }

    void SessionEndpoint::handle_session_init(
        std::span<const std::byte> payload, std::shared_ptr<path::TransitHop> thop)
    {
        log::debug(logcat, "SessionEndpoint::handle_session_init (relay)");
        std::shared_ptr<session::InboundSession> new_session{};
        try
        {
            new_session = std::make_shared<session::InboundRelaySession>(*this, std::move(thop), std::move(payload));
        }
        catch (const std::exception& e)
        {
            log::info(logcat, "Inbound session rejected: {}", e.what());
            return;
        }
        log::debug(logcat, "SessionEndpoint::handle_session_init (relay) calling post_init");
        session_post_init(std::move(new_session));
    }

    void SessionEndpoint::session_post_init(std::shared_ptr<session::InboundSession> new_session)
    {
        // FIXME: for now only tun clients can have inbound sessions, but eventually that will
        //        not be the case and we'll need to "if tun" this.
        if (!map_session_v6(*new_session))
        {
            log::warning(
                logcat,
                "Unable to map session to tun IP (or not allowing inbound sessions); dropping inbound session from {}",
                new_session->remote());
            return;
        }

        // TODO FIXME: this is racy, e.g. if two clients establish a session to each other at the
        // same time, then they can drop different ones.  We should instead use a decision metric
        // for dropping that decides the same way on both sides (e.g. prefer session initiated by
        // the side with the smaller pubkey).
        // FIXME: If the initiator does not get our response in time, they will try again
        // to establish a session; in that case we should replace what we have.
        auto& s = _sessions[new_session->remote()];

        // if there was already a session to the remote, we're trampling it, so clear it from
        // _session_tags
        if (s)
            _session_tags.erase(s->inbound_tag());

        auto* sptr = new_session.get();
        s = std::move(new_session);
        _session_tags[s->inbound_tag()] = s;
        log::debug(logcat, "sending session_init_accept");
        sptr->session_init_accept();
    }

    void SessionEndpoint::publish_client_contact(std::string_view encrypted_cc)
    {
        auto now = std::chrono::steady_clock::now();
        ++cc_count;
        // Send our CC down each inbound session so that everyone who is already connected to us
        // gets it pushed to them without having to always poll the network for updates.
        for (const auto& [addr, session] : _sessions)
        {
            // don't publish client contact to other end of outbound session
            if (session->is_outbound)
                continue;
            log::debug(
                logcat,
                "Publishing ClientContact#{} to remote on inbound session (remote:{})",
                cc_count,
                session->remote());

            session->publish_client_contact(encrypted_cc);
        }

        // Pick four random inbound paths to publish on, and then on each one we send along a 0-3
        // location indicating where we want it to forward it (e.g. 0 means DHT-closest, 1 means 2nd
        // closest, etc.).
        std::vector<path::Path*> paths;
        paths.resize(path::CC_PUBLISH_LOCATIONS);
        auto end = std::ranges::sample(
            active_paths() | std::views::transform([](auto& p) { return &p; }),
            paths.begin(),
            path::CC_PUBLISH_LOCATIONS,
            srouter::csrng);
        paths.resize(std::distance(paths.begin(), end));
        if (paths.empty())
        {
            // This should be impossible: we should only have triggered a publish once we reached
            // our target number of active paths, but somehow found no active paths!
            log::error(logcat, "Internal error: attempt to publish CC with no active paths!");
            assert(false);
            return;
        }
        std::shuffle(paths.begin(), paths.end(), srouter::csrng);

        // Tracks number of successes and number of outstanding requests so that we can log success
        // (or error) when the last response comes back:
        auto remaining_success = std::make_shared<std::pair<int, int>>(path::CC_PUBLISH_LOCATIONS, 0);

        for (int location = 0; location < path::CC_PUBLISH_LOCATIONS; location++)
        {
            // % because we might have fewer than path::CC_PUBLISH_LOCATIONS, and if that happens we
            // just use some paths for multiple locations:
            auto& p = *paths[location % paths.size()];
            log::debug(logcat, "Publishing ClientContact to location {} via {}", location, p);
            p.publish_client_contact(
                encrypted_cc,
                location,
                [started = now, remaining_success, via = p.terminal_rid(), location, cc_num = cc_count](auto resp) {
                    auto elapsed =
                        std::chrono::round<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);

                    log::debug(
                        logcat,
                        "{} CC#{} publish[{}] via relay {} in {}",
                        resp.ok()            ? "Successful"
                            : resp.timed_out ? "Timeout during"
                                             : "Error during",
                        cc_num,
                        location,
                        via,
                        elapsed);
                    if (!resp.ok())
                        log::debug(logcat, "CC publish error response: {}", buffer_printer(resp.body));

                    auto& [remaining, success] = *remaining_success;
                    remaining--;
                    if (resp.ok())
                        success++;

                    if (not remaining)
                    {  // This is the last response
                        log::log(
                            logcat,
                            not success                                    ? log::Level::err
                                : success < path::CC_PUBLISH_LOCATIONS / 2 ? log::Level::warn
                                                                           : log::Level::info,
                            "CC#{} publish success to {}/{} publish locations in {}",
                            cc_num,
                            success,
                            path::CC_PUBLISH_LOCATIONS,
                            elapsed);
                    }
                });
        }
    }

    std::optional<std::string_view> SessionEndpoint::fetch_auth_token(const NetworkAddress& remote) const
    {
        std::optional<std::string_view> ret = std::nullopt;

        if (auto itr = _auth_tokens.find(remote); itr != _auth_tokens.end())
            ret = itr->second;

        return ret;
    }

    std::shared_ptr<session::Session> SessionEndpoint::initiate_remote_session(
        const NetworkAddress& remote,
        std::function<void(session::Session& session)> on_attempted,
        std::optional<std::chrono::milliseconds> timeout)
    {
        return router._jq->call_get([this, &remote, &on_attempted, &timeout] {
            std::shared_ptr<session::Session> s{nullptr};
            if (auto it = _sessions.find(remote); it != _sessions.end())
                s = it->second;
            if (s && !s->is_closed() && !s->is_unreachable())
            {
                if (on_attempted)
                {
                    if (s->is_established())
                        on_attempted(*s);
                    else
                    {
                        assert(s->is_outbound);  // Inbound sessions are always established
                        // We have an already-in-progress but not-yet-established session, so just
                        // hook the callback up to it to be fired when it finishes establishing:
                        static_cast<session::OutboundSession*>(s.get())->on_established(
                            std::move(on_attempted), timeout);
                    }
                }
            }
            else
            {
                auto tag = next_tag();
                try
                {
                    if (remote.client())
                        s = router._jq->make_shared<session::OutboundClientSession>(
                            remote, *this, tag, std::move(on_attempted), timeout);
                    else
                        s = router._jq->make_shared<session::OutboundRelaySession>(
                            remote, *this, tag, std::move(on_attempted), timeout);

                    // A relay session resolves its RC during construction, so if the relay has no
                    // RC we already know the session can never establish.  Don't register it: the
                    // caller gets nullptr, and a later attempt builds a fresh session that looks
                    // the RC up again rather than reusing this verdict.
                    if (s->is_unreachable())
                        return std::shared_ptr<session::Session>{nullptr};

                    _session_tags.emplace(tag, s);
                    _sessions[remote] = s;
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error{"Error creating session to remote {}: {}"_format(remote, e.what())};
                }
            }

            return s;
        });
    }

    session_tag SessionEndpoint::next_tag()
    {
        // zero tag used to represent a session init for convenience
        while (_session_tags.contains(last_tag) || last_tag == 0)
            last_tag++;
        return last_tag;
    }

    void SessionEndpoint::for_each_session(
        std::function<void(const NetworkAddress&, const session::Session&)> visit) const
    {
        for (const auto& [addr, s] : _sessions)
            visit(addr, *s);
    }

    std::vector<path::Path*> SessionEndpoint::outbound_session_paths() const
    {
        std::vector<path::Path*> paths;

        for (const auto& [remote, session] : _sessions)
        {
            if (not session->is_outbound)
                continue;

            if (auto* outbound = dynamic_cast<session::OutboundSession*>(session.get()))
                for (auto& path : outbound->active_paths())
                    paths.push_back(&path);
        }

        return paths;
    }

    std::optional<std::pair<uint16_t, std::shared_ptr<session::Session>>> SessionEndpoint::map_udp_remote_port(
        const NetworkAddress& remote, uint16_t port)
    {
        return router._jq->call_get([&]() -> std::optional<std::pair<uint16_t, std::shared_ptr<session::Session>>> {
            // Port selection: we pick something random in the 49152-60000 range to start from, as
            // that range (up to 60999) is common to all modern OSes for ephemeral addresses, and so
            // at least our first thousand ports will look like a normal random ephemeral port.
            // (Otherwise we just keep going, wrapping around from 65535 back to 1024).
            if (_next_udp_client_port == 0)
                _next_udp_client_port = std::uniform_int_distribution<uint16_t>{49152, 60000}(csrng);

            std::pair<uint16_t, std::shared_ptr<session::Session>> result;
            auto& [local_port, session] = result;
            session = initiate_remote_session(remote);  // throws on immediate error
            if (!session)
            {
                log::debug(logcat, "Not mapping a UDP port for {}: remote is unreachable", remote);
                return std::nullopt;
            }

            mapped_remote target{.remote = remote, .port = port};
            auto h_it = _udp_handles.find(target);
            bool existing = h_it != _udp_handles.end();
            if (!existing)
            {
                // Construct before inserting and counting: a throwing socket constructor would
                // otherwise leave behind an entry with a holder that nothing can ever release.
                auto socket = std::make_unique<quic::UDPSocket>(
                    router.loop().get_event_base(),
                    quic::Address{"::1", 0},
                    /*gso=*/false,
                    [this, target](quic::Packet&& pkt) {
                        // FIXME: cache most recently used mapping/session/etc.?
                        //        i.e. if this packet is for the same remote as the last packet
                        //        we can skip the map lookup.

                        std::shared_ptr<session::Session> session;
                        try
                        {
                            session = initiate_remote_session(target.remote);
                        }
                        catch (const std::exception& e)
                        {
                            log::warning(
                                logcat,
                                "Received local mapped UDP packet, but unable to obtain/initiate a session with {}: {}",
                                target.remote,
                                e.what());
                            return;
                        }
                        if (!session)
                        {
                            log::warning(
                                logcat,
                                "Received local mapped UDP packet for unreachable remote {}, dropping",
                                target.remote);
                            return;
                        }

                        // `instance` contains the targetted remote, and the app source port, and is our
                        // lookup key to see if we've already received data from that same app source port
                        // aimed at our intermediate port
                        const uint16_t app_source_port = pkt.path.remote.port();
                        mapped_remote instance{.remote = target.remote, .port = app_source_port};

                        uint16_t& mapped_port = _udp_client_ports[instance];
                        if (mapped_port == 0)
                        {  // We just auto-vivified it
                            uint16_t start_port = _next_udp_client_port;
                            mapped_remote new_port{.remote = target.remote, .port = start_port};
                            while (not _udp_return_ports.try_emplace(new_port, app_source_port).second)
                            {
                                new_port.port++;
                                if (new_port.port < 1024)
                                    new_port.port = 1024;
                                if (new_port.port == start_port)
                                {
                                    // This seems very unlikely: it would mean we have mapped ~64k
                                    // *distinct* localhost application ports
                                    log::error(logcat, "Run out of pseudo-UDP ports to use");
                                    _udp_client_ports.erase(instance);
                                    return;
                                }
                            }
                            if (auto it = _udp_handles.find(target); it != _udp_handles.end())
                                it->second.cports.push_back(instance);
                            mapped_port = new_port.port;
                            log::debug(
                                logcat,
                                "New client UDP packet from localhost:{} to {}:{} mapped to pseudo-port {}",
                                app_source_port,
                                target.remote,
                                target.port,
                                mapped_port);
                        }

                        // Construct a UDP packet with source port of our pseudo-port, and dest port of the
                        // remote mapped port (so that return packets get picked up correctly).
                        auto packet =
                            IPPacket::make_udp_packet(quic::ipv6{}, mapped_port, quic::ipv6{}, target.port, pkt.data());

                        session->send_session_data_message(packet, traffic_type::UDP);
                    });

                h_it = _udp_handles.try_emplace(target).first;
                h_it->second.socket = std::move(socket);
            }

            h_it->second.holders++;
            local_port = h_it->second.socket->address().port();
            log::debug(
                logcat,
                "{} mapped UDP port ({}) for remote {}:{}",
                existing ? "Using existing" : "Created new",
                local_port,
                remote,
                port);

            return result;
        });
    }

    void SessionEndpoint::unmap_udp_remote_port(const NetworkAddress& remote, uint16_t port)
    {
        // As in map_udp_remote_port: these containers belong to the job queue thread, and an
        // embedded caller can be on any thread at all.
        router._jq->call_get([&] {
            mapped_remote rem{.remote = remote, .port = port};

            auto it = _udp_handles.find(rem);
            if (it == _udp_handles.end())
            {
                log::debug(logcat, "Nothing to unmap: {}:{} is not currently a mapped UDP port", remote, port);
                return;
            }

            auto& [sock, cports, holders] = it->second;
            if (--holders > 0)
            {
                log::debug(
                    logcat, "Released a claim on {}:{}; {} still held, keeping it mapped", remote, port, holders);
                return;
            }

            for (auto& c : cports)
            {
                if (auto cit = _udp_client_ports.find(c); cit != _udp_client_ports.end())
                {
                    _udp_return_ports.erase(mapped_remote{.remote = remote, .port = cit->second});
                    _udp_client_ports.erase(cit);
                }
            }

            auto local_port = sock->address().port();
            _udp_handles.erase(it);

            log::debug(logcat, "Unmapped localhost:{} -> {}:{} UDP mapping", local_port, remote, port);
        });
    }

    TCPConnection* SessionEndpoint::tunnel_tcp_connection(
        const mapped_remote& target, bufferevent* bev, TCPConnection::fd_t fd)
    {
        std::shared_ptr<session::Session> session;
        try
        {
            // As with UDP, re-obtaining the session per connection is what lets a mapping survive an
            // idle timeout and re-establish itself on the next use.
            session = initiate_remote_session(target.remote);
        }
        catch (const std::exception& e)
        {
            log::warning(
                logcat, "Cannot obtain a session to {} for a tunnelled TCP connection: {}", target.remote, e.what());
            return nullptr;
        }

        if (!session)
        {
            log::warning(logcat, "Dropping TCP connection for unreachable remote {}", target.remote);
            return nullptr;
        }

        if (auto accepts = session->remote_accepts_tcp(); accepts.has_value() && !*accepts)
        {
            log::warning(logcat, "Dropping TCP connection: {} does not accept tunnelled TCP", target.remote);
            return nullptr;
        }

        return session->tunnel().connect_stream(bev, fd, target.port);
    }

    std::optional<std::pair<uint16_t, std::shared_ptr<session::Session>>> SessionEndpoint::map_tcp_remote_port(
        const NetworkAddress& remote, uint16_t port)
    {
        return router._jq->call_get([&]() -> std::optional<std::pair<uint16_t, std::shared_ptr<session::Session>>> {
            std::pair<uint16_t, std::shared_ptr<session::Session>> result;
            auto& [local_port, session] = result;

            session = initiate_remote_session(remote);  // throws on immediate error
            if (!session)
            {
                log::debug(logcat, "Not mapping a TCP port for {}: remote is unreachable", remote);
                return std::nullopt;
            }

            // A remote we know cannot terminate a tunnelled stream gets refused now rather than at
            // connection time.  Not knowing (no client contact yet) is not a refusal: we map, and
            // find out when the contact arrives.
            if (auto accepts = session->remote_accepts_tcp(); accepts.has_value() && !*accepts)
            {
                log::debug(logcat, "Not mapping a TCP port for {}: remote does not accept tunnelled TCP", remote);
                return std::nullopt;
            }

            mapped_remote target{.remote = remote, .port = port};

            auto it = _tcp_handles.find(target);
            if (it == _tcp_handles.end())
            {
                std::shared_ptr<TCPHandle> listener;
                try
                {
                    listener = TCPHandle::make_server(
                        router.loop(), [this, target](bufferevent* bev, TCPConnection::fd_t fd) -> TCPConnection* {
                            return tunnel_tcp_connection(target, bev, fd);
                        });
                }
                catch (const std::exception& e)
                {
                    log::error(logcat, "Failed to bind a local TCP port for {}: {}", remote, e.what());
                    return std::nullopt;
                }

                it = _tcp_handles.try_emplace(target).first;
                it->second.listener = std::move(listener);
            }

            it->second.holders++;
            local_port = it->second.listener->port();

            log::debug(logcat, "Mapped TCP [::1]:{} -> {}:{}", local_port, remote, port);
            return result;
        });
    }

    void SessionEndpoint::unmap_tcp_remote_port(const NetworkAddress& remote, uint16_t port)
    {
        // As in map_tcp_remote_port: these containers belong to the job queue thread, and an
        // embedded caller can be on any thread at all.
        router._jq->call_get([&] {
            auto it = _tcp_handles.find(mapped_remote{.remote = remote, .port = port});
            if (it == _tcp_handles.end())
            {
                log::debug(logcat, "Nothing to unmap: {}:{} is not currently a mapped TCP port", remote, port);
                return;
            }

            if (--it->second.holders > 0)
            {
                log::debug(
                    logcat,
                    "Released a claim on {}:{}; {} still held, keeping it mapped",
                    remote,
                    port,
                    it->second.holders);
                return;
            }

            auto local_port = it->second.listener->port();
            _tcp_handles.erase(it);

            // Releasing the last claim takes the mapping's connections with it: holding the claim is
            // what keeps them alive, so there is nothing left to keep them for.
            if (auto* session = get_session(remote))
                if (auto* tunnel = session->maybe_tunnel())
                    tunnel->close_connections_for(port);

            log::debug(logcat, "Unmapped localhost:{} -> {}:{} TCP mapping", local_port, remote, port);
        });
    }

}  //  namespace srouter::handlers
