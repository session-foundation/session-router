#include "nodedb.hpp"

#include "link/link_manager.hpp"
#include "util/file.hpp"
#include "util/logging/buffer.hpp"
#include "util/random.hpp"
#include "util/time.hpp"
#include "util/zstd.hpp"

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/loop.hpp>
#include <oxenc/base32z.h>
#include <sodium/crypto_generichash.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <iterator>
#include <random>
#include <ranges>
#include <unordered_map>
#include <utility>

namespace srouter
{
    static auto logcat = srouter::log::Cat("nodedb");

    std::array<int, 3> NodeDB::db_stats() const { return {num_rcs(), num_rids(), num_bootstraps()}; }

    template <typename RCContainer, std::predicate<const RelayContact&> Pred, typename RNG>
    static std::vector<const RelayContact*> sample_rcs(
        Router& router, const RCContainer& rcs, int n, const Pred& predicate, RNG& rng, bool shuffle)
    {
        auto now = srouter::time_now_ms();
        const auto& blacklist = router.config().paths.snode_blacklist;

        std::vector<const RelayContact*> rand;
        rand.resize(n);
        int admitted = 0;

        for (const RelayContact& rc : rcs)
        {
            if (rc.is_expired(now))
                continue;
            if (router.is_service_node)
            {
                if (rc.router_id() == router.id())
                    continue;
            }
            else if (blacklist.contains(rc.router_id()))
                continue;
            if (predicate and not predicate(rc))
                continue;

            auto pos = admitted < n ? admitted : std::uniform_int_distribution<int>{0, admitted}(rng);
            admitted++;
            if (pos < n)
                rand[pos] = &rc;
        }
        if (admitted < n)
            rand.resize(admitted);
        if (shuffle && rand.size() > 1)
            std::ranges::shuffle(rand, rng);
        return rand;
    }

    // Hash a serialized RelayContact into 64-bits for identification.
    // 64-bits is large enough, as we don't need to worry about collisions
    //
    // Throws if key "t" is not found (or if somehow the input is not a valid bt-dict)
    static RCHash bucket_hash(std::string_view serialized_rc)
    {
        RCHash ret;

        crypto_generichash_blake2b_state h;
        crypto_generichash_blake2b_init(&h, nullptr, 0, sizeof(ret));

        oxenc::bt_dict_consumer btdc{serialized_rc};

        if (!btdc.skip_until("t"sv))
            assert(!"Serialized RC did not contain a timestamp.");

        // hash everything up to the literal byte "t" of the key (the key is "1:t")
        auto time_key_and_data = btdc.next_integer<uint64_t>();
        size_t to_hash = time_key_and_data.first.data() - serialized_rc.data();
        crypto_generichash_blake2b_update(&h, reinterpret_cast<const uint8_t*>(serialized_rc.data()), to_hash);

        // hash everything starting from the beginning of the next key to the start of the signature
        // NOTE: because the size and colon of that key are not hashed, multi-byte keys will break
        // this, so if we ever decide RCs need a multi-byte key we need to make oxenc expose a bit
        // more data.
        auto after_time = btdc.key();
        if (after_time != "~"sv)
        {
            if (!btdc.skip_until("~"sv))
                assert(!"Serialized RC did not contain a timestamp.");
            auto sig_key_and_data = btdc.next_string();
            auto after_size = sig_key_and_data.first.data() - after_time.data();
            crypto_generichash_blake2b_update(&h, reinterpret_cast<const uint8_t*>(after_time.data()), after_size);
        }

        crypto_generichash_blake2b_final(&h, reinterpret_cast<uint8_t*>(&ret), sizeof(ret));

        // big_to_host so any system will have the same numerical value stored
        return ret;
    }

    // A bucket hash is the XOR of the hashes of the RCs in the bucket; since XOR is its own inverse
    // this both adds and removes an RC's contribution.
    static void xor_bucket_hash(RCHash& bucket_hash, RCHash rc_hash)
    {
        static_assert(sizeof(RCHash) == sizeof(uint64_t));
        *reinterpret_cast<uint64_t*>(&bucket_hash) ^= *reinterpret_cast<uint64_t*>(&rc_hash);
    }

    static uint8_t bucket_of(const RouterID& rid)
    {
        // choice of which byte is arbitrary, but avoid early bytes for clustered vanity keys
        // 128 buckets total, so mask off MSB.
        return static_cast<uint8_t>(rid.as_array()[16] & std::byte{0x7f});
    }

    void NodeDB::update_rc_buckets(const RelayContact& rc, bool added)
    {
        const auto& rid = rc.router_id();
        auto bucket = bucket_of(rid);
        auto& hashes = rc_hashes[bucket];
        auto recorded = hashes.try_emplace(rid).first;

        // We take out the hash we recorded when this RC was added, which is not necessarily a hash of
        // the RC we have here.  (For an RC we don't have yet this is all-zeros, i.e. a no-op.)
        xor_bucket_hash(rc_bucket_hashes[bucket], recorded->second);

        if (added)
        {
            recorded->second = bucket_hash(rc.view());
            xor_bucket_hash(rc_bucket_hashes[bucket], recorded->second);
        }
        else
            hashes.erase(recorded);
    }

    std::vector<const RelayContact*> NodeDB::get_n_random_rcs(
        int n, bool shuffle, const std::function<bool(const RelayContact&)>& predicate) const
    {
        assert(_router.loop().inside());
#ifdef SROUTER_DEBUG_PATH_SEED
        if (auto& s = _router.config().paths.debug_path_seed)
        {
            std::vector<std::reference_wrapper<const RelayContact>> rcs;
            rcs.reserve(known_rcs.size());
            for (const auto& rc : known_rcs | std::views::values)
                rcs.push_back(std::cref(rc));
            // We need a sorted list of known rcs because of the potentially non-reproducible order
            // of elements in an unordered map:
            std::ranges::sort(
                rcs, [](const RelayContact& a, const RelayContact& b) { return a.router_id() < b.router_id(); });
            std::mt19937_64 rng{*s};
            return sample_rcs(_router, rcs, n, predicate, rng, shuffle);
        }
#endif

        return sample_rcs(_router, known_rcs | std::views::values, n, predicate, srouter::csrng, shuffle);
    }

    const RelayContact* NodeDB::get_random_rc(const std::function<bool(const RelayContact&)>& predicate) const
    {
        auto randos = get_n_random_rcs(1, false, predicate);
        return randos.empty() ? nullptr : randos.front();
    }

    std::vector<const RelayContact*> NodeDB::get_n_random_edge_rcs(
        int n, bool shuffle, const std::function<bool(const RelayContact&)>& predicate) const
    {
        assert(_router.loop().inside());
        auto& strict = _router.config().paths.strict_edges;
        if (_router.is_service_node || strict.empty())
            return get_n_random_rcs(n, shuffle, predicate);

        n = std::min(n, static_cast<int>(strict.size()));

        // With strict edges the set of edges is typically small, so we iterate through just those
        // edges rather than sampling from *everything* with an "is in strict" lookups added to the
        // predicate.
        std::vector<std::reference_wrapper<const RelayContact>> strict_rcs;
        for (const auto& rid : strict)
            if (auto* rc = get_rc(rid))
                strict_rcs.emplace_back(std::cref(*rc));

#ifdef SROUTER_DEBUG_PATH_SEED
        if (auto& s = _router.config().paths.debug_path_seed)
        {
            std::ranges::sort(
                strict_rcs, [](const RelayContact& a, const RelayContact& b) { return a.router_id() < b.router_id(); });
            std::mt19937_64 rng{*s};
            return sample_rcs(_router, strict_rcs, n, predicate, rng, shuffle);
        }
#endif

        return sample_rcs(_router, strict_rcs, n, predicate, srouter::csrng, shuffle);
    }

    void NodeDB::bootstrap()
    {
        assert(_router.loop().inside());
        assert(!_bootstraps.empty());
        _bootstrap_running = true;

        struct bs_data
        {
            NodeDB& nodedb;
            size_t rc_i = 0;
            std::string body;
            RouterID source;

            // Shared pointer to ourself to keep us alive.  This is released once we run out of rcs,
            // or get a successful fetch.
            std::shared_ptr<void> keep_alive;

            void try_next()
            {
                if (nodedb._router.is_stopping())
                {
                    log::debug(logcat, "Aborting bootstrap because of router stop");
                    keep_alive.reset();
                    return;
                }

                if (rc_i >= nodedb._bootstraps.size())
                {
                    log::debug(logcat, "Bootstrapping failed: bootstraps list exhausted without any success");
                    auto ka = std::move(keep_alive);
                    nodedb.on_bootstrap_done(false);
                    return;
                }

                auto& rc = nodedb._bootstraps[rc_i++];
                source = rc.router_id();
                log::debug(
                    logcat,
                    "Initiating bootstrap request to {} @ {}",
                    rc.router_id().to_network_address(true),
                    rc.addr());
                auto [conn, control] = nodedb._router.link_endpoint().bootstrap_connect(rc);
                control->command("bfetch_rcs", body, [this, conn](quic::message m) {
                    nodedb._router._jq->call_soon([this, m = std::move(m)] {
                        if (not m)
                            log::warning(logcat, "Bootstrap fetch failed: {}", m.timed_out ? "timeout" : m.body());

                        else if (nodedb.handle_bootstrap_result(source, m.body()))
                        {
                            auto ka = std::move(keep_alive);
                            nodedb.on_bootstrap_done(true);
                            return;
                        }

                        try_next();
                    });

                    conn->close_connection();
                });
            }
        };
        auto bs = std::make_shared<bs_data>(*this);
        bs->keep_alive = bs;

        bs->body = "de";

        bs->try_next();
    }

    void NodeDB::purge_rcs(sys_ms now)
    {
        assert(_router.loop().inside());
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_router.is_stopping() || not _router.is_running())
        {
            log::debug(logcat, "NodeDB unable to continue purge ticking -- router is stopped!");
            return;
        }

        remove_rcs_if([this, now](const RelayContact& rc) -> bool {
            // if for some reason we stored an RC that isn't a valid router
            // purge this entry
            if (not rc.addr().is_public())
            {
                log::trace(logcat, "Removing {}: address {} is not public", rc.router_id(), rc.addr());
                return true;
            }

            // clear out a fully expired RC
            if (rc.is_expired(now))
            {
                log::trace(logcat, "Removing {}: RC is expired", rc.router_id());
                return true;
            }

            if (_router.is_service_node)
            {
                // if we don't have the registered relay list yet don't remove the entry
                if (not has_registered_relays())
                {
                    log::trace(
                        logcat,
                        "Skipping check on {}: have not received oxend registered relay list yet",
                        rc.router_id());
                    return false;
                }

                if (not is_registered(rc.router_id()))
                {
                    log::trace(logcat, "Removing {}: not a valid router", rc.router_id());
                    return true;
                }
            }
            else
            {
                // Clients do not have an authoritative relay list, so we have no checks equivalent
                // to the above ones.
                log::trace(logcat, "Not removing {}: we are a client and it looks fine", rc.router_id());
                return false;
            }

            return false;
        });

        if (num_rcs() < MIN_ACTIVE_RCS and not _bootstraps.empty() and not _bootstrap_running)
        {
            log::warning(logcat, "Purging expired relays resulted in too few RCs; falling back to bootstrap mode");
            _bootstrap_fails = 0;
            bootstrap();
        }
    }

    std::filesystem::path NodeDB::get_path_by_pubkey(const RouterID& pubkey, const std::filesystem::path& ext) const
    {
        return _root / std::filesystem::path{pubkey.to_string()}.replace_extension(ext);
    }

    void NodeDB::fetch_rcs(std::function<void(bool success)> on_done)
    {
        assert(_router.loop().inside());

        path::Path* selected_path = _router.session_endpoint().get_random_active_path();
        if (!selected_path)
        {
            log::debug(logcat, "NodeDB fetch rcs, skipping because we have no paths.");
            if (on_done)
                on_done(false);
            return;
        }

        oxenc::bt_dict_producer btdp;

        // bt_list_producer::append(std::array) appends as a sublist, so append each element as
        // a span instead
        auto btlp = btdp.append_list("b"sv);
        for (const auto& h : rc_bucket_hashes)
        {
            btlp.append(std::span(h));
        }

        log::debug(logcat, "Fetching RCs from {}", selected_path->terminal_rid());

        selected_path->fetch_relay_contacts(btdp.span<std::byte>(), [this, on_done = std::move(on_done)](auto resp) {
            std::string error;
            if (resp.ok())
            {
                try
                {
                    size_t fetched_count = 0;
                    size_t n_new = 0, n_changed = 0, n_identical = 0;
                    std::unordered_set<uint8_t> buckets_hit;

                    oxenc::bt_dict_consumer btdc{resp.body};
                    if (btdc.skip_until("!"sv))
                    {
                        if (auto sv = btdc.consume_string_view(); sv != "OK"sv)
                            throw std::runtime_error{std::string(sv)};
                    }

                    btdc.required("r");
                    auto btlc = btdc.consume_list_consumer();
                    while (!btlc.is_finished())
                    {
                        auto rc = RelayContact{btlc.consume_string_view(), _router.netid()};
                        const auto& rid = rc.router_id();
                        if (!known_rids.contains(rid))
                        {
                            log::info(logcat, "Got RC from relay, but we haven't seen its RouterID, ignoring.");
                            continue;
                        }
                        auto bucket = bucket_of(rid);
                        log::debug(logcat, "Received RC for relay {} in bucket {:x}", rid, bucket);

                        buckets_hit.insert(bucket);
                        if (auto it = rc_hashes[bucket].find(rid); it == rc_hashes[bucket].end())
                            n_new++;
                        else if (it->second == bucket_hash(rc.view()))
                            n_identical++;
                        else
                        {
                            n_changed++;
                            log::debug(logcat, "RC for {} differs from the one we hold", rid);
                        }

                        if (auto [stored, gossip] = put_rc(std::move(rc)); !stored)
                            log::debug(logcat, "Not inserting RC for {}, seen too recently.", rid);
                        fetched_count++;
                    }
                    // A large "identical" count means the relay sent us buckets whose contents
                    // already match ours, i.e. its bucket hashes are stale rather than its RCs
                    // being different from ours.
                    log::debug(
                        logcat,
                        "RC fetch gave {} RCs across {} buckets: {} new, {} changed, {} identical"sv,
                        fetched_count,
                        buckets_hit.size(),
                        n_new,
                        n_changed,
                        n_identical);
                    _last_rc_fetch = time_now_ms();

                    if (!_pending_rc_lookups.empty())
                    {
                        log::debug(logcat, "Processing {} queued RC lookups", _pending_rc_lookups.size());
                        auto pending = std::move(_pending_rc_lookups);
                        _pending_rc_lookups.clear();
                        for (auto& [rid, func] : pending)
                        {
                            try
                            {
                                auto* rc = get_rc(rid);
                                func(rc ? std::optional{*rc} : std::nullopt);
                            }
                            catch (const std::exception& e)
                            {
                                log::error(logcat, "Uncaught exception processing queued RC lookup: {}", e.what());
                            }
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    error = e.what();
                }
            }
            else
            {
                error = resp.timed_out ? "timed out" : "failed: {}"_format(resp.body);
            }

            if (!error.empty())
            {
                log::warning(logcat, "RC bucket fetch failed: {}", error);

                // Fail any queued lookups that were waiting for the initial fetch
                if (!_pending_rc_lookups.empty())
                {
                    log::debug(logcat, "Failing {} queued RC lookups", _pending_rc_lookups.size());
                    auto pending = std::move(_pending_rc_lookups);
                    _pending_rc_lookups.clear();
                    for (auto& [rid, func] : pending)
                    {
                        try
                        {
                            func(std::nullopt);
                        }
                        catch (const std::exception& e)
                        {
                            log::error(logcat, "Uncaught exception processing queued RC lookup: {}", e.what());
                        }
                    }
                }
            }

            if (on_done)
                on_done(error.empty());
        });
    }

    void NodeDB::lookup_rc(const RouterID& rid, std::function<void(std::optional<RelayContact>)> func)
    {
        assert(_router.loop().inside());

        if (auto* rc = get_rc(rid))
        {
            log::debug(logcat, "lookup_rc: {} found locally", rid);
            func(*rc);
            return;
        }

        // If we haven't completed an initial RC fetch yet, queue the lookup to be retried
        // once the first fetch completes (this happens during startup before RCs are available).
        if (_last_rc_fetch == sys_ms{})
        {
            log::debug(logcat, "lookup_rc: {} not found, initial RC fetch not yet complete; queueing", rid);
            _pending_rc_lookups.emplace_back(rid, std::move(func));
            return;
        }

        if (!known_rids.contains(rid))
            log::debug(logcat, "lookup_rc: {} not in known RID set; treating as unknown", rid);
        else
            log::debug(logcat, "lookup_rc: {} in RID set but no RC available", rid);

        func(std::nullopt);
    }

    void NodeDB::fetch_rids()
    {
        assert(_router.loop().inside());
        if (_router.is_stopping() || not _router.is_running())
        {
            log::debug(logcat, "NodeDB skipping RouterID fetch -- router is stopped!");
            return;
        }

        auto results = std::make_shared<std::unordered_map<RouterID, std::unordered_set<RouterID>>>();
        auto result_count = std::make_shared<size_t>(0);
        std::vector<path::Path*> selected_paths;

        // Our inbound paths are the sources we trust most here: we picked their terminals at
        // random, for reasons unconnected to whoever we happen to be talking to.
        std::unordered_set<RouterID> inbound_sources;

        for (auto& path : _router.session_endpoint().active_paths())
        {
            if (selected_paths.size() >= RID_SOURCE_COUNT)
                break;
            auto [itr, inserted] = results->emplace(path.terminal_rid(), std::unordered_set<RouterID>{});
            if (inserted)
            {
                inbound_sources.insert(path.terminal_rid());
                selected_paths.push_back(&path);
            }
        }

        // Inbound paths are also the utility paths we look up and publish client contacts over, so
        // having none of them means we are cut off from the network rather than merely short of
        // sources.  Nothing is gained by rebuilding our view of it from outbound sources alone.
        if (inbound_sources.empty())
        {
            log::debug(logcat, "Have no inbound paths, not fetching RouterIDs yet.");
            _router._jq->call_later(100ms, [this] { fetch_rids(); });
            return;
        }

        // Short of inbound paths, make the number up from the paths our outbound sessions are
        // using.  Those terminals were chosen to reach some particular remote rather than at random,
        // so a peer we are talking to has a hand in who they are; handle_fetched_router_ids makes
        // them corroborate rather than decide.
        if (selected_paths.size() < RID_SOURCE_COUNT)
        {
            auto extra = _router.session_endpoint().outbound_session_paths();
            std::ranges::shuffle(extra, srouter::csrng);

            for (auto* path : extra)
            {
                if (selected_paths.size() >= RID_SOURCE_COUNT)
                    break;
                auto [itr, inserted] = results->emplace(path->terminal_rid(), std::unordered_set<RouterID>{});
                if (inserted)
                    selected_paths.push_back(path);
            }
        }

        if (selected_paths.size() < RID_SOURCE_COUNT)
            log::info(
                logcat,
                "Fetching RouterIDs from {} sources ({} of them inbound); wanted {}, but have no more paths to ask",
                selected_paths.size(),
                inbound_sources.size(),
                RID_SOURCE_COUNT);

        for (auto* path : selected_paths)
        {
            auto result_cb = [this, results, result_count, inbound_sources, source = path->terminal_rid()](auto resp) {
                (*result_count)++;
                if (not resp.ok())
                {
                    log::warning(
                        logcat,
                        "RID fetch from {} {}",
                        source,
                        resp.timed_out ? "timed out" : "failed: {}"_format(resp.body));
                }
                else
                {
                    try
                    {
                        auto& router_ids = results->at(source);
                        oxenc::bt_dict_consumer btdc{resp.body};

                        btdc.required("r");

                        {
                            auto sublist = btdc.consume_list_consumer();

                            while (not sublist.is_finished())
                                router_ids.emplace(sublist.consume_span<uint8_t, 32>());
                        }
                    }
                    catch (const std::exception& e)
                    {
                        log::warning(logcat, "Error handling fetch RouterIDs response: {}", e.what());
                        results->at(source).clear();
                    }
                }
                if (*result_count == results->size())
                {
                    // Whatever happens while applying the results, the next round has to get
                    // scheduled: dropping it would stop us fetching RouterIDs for good.
                    bool conclusive = false;
                    try
                    {
                        conclusive = handle_fetched_router_ids(*results, inbound_sources);
                    }
                    catch (const std::exception& e)
                    {
                        log::error(logcat, "Error applying fetched RouterIDs: {}", e.what());
                    }

                    _router._jq->call_later(
                        conclusive ? FETCH_INTERVAL : FETCH_RETRY_INTERVAL, [this] { fetch_rids(); });
                }
            };
            path->send_path_control_message("fetch_rids"sv, {}, std::move(result_cb));
        }
    }

    bool NodeDB::handle_fetched_router_ids(
        const std::unordered_map<RouterID, std::unordered_set<RouterID>>& results,
        const std::unordered_set<RouterID>& inbound_sources)
    {
        assert(_router.loop().inside());

        const size_t asked = results.size();

        // A RouterID is accepted when a strict majority of the sources we asked affirm it -- 3 of 5,
        // 3 of 4, 2 of 3, and so on down -- and that majority has to include one of our own inbound
        // sources.  An outbound path's terminal is reached on behalf of some remote, so left to
        // themselves those sources could walk us onto a different view of the network; where every
        // source is inbound the requirement costs nothing, as any majority contains one.
        //
        // A source that failed, timed out or sent us nonsense simply affirms nothing, which is the
        // same to us as one that answered without it.
        const size_t needed = asked / 2 + 1;

        std::unordered_set<RouterID> accepted{};

        for (const auto& [source, rids] : results)
        {
            for (const auto& rid : rids)
            {
                if (accepted.contains(rid))
                    continue;

                size_t agree = 0;
                bool inbound_agrees = false;
                for (const auto& [other, other_rids] : results)
                    if (other_rids.contains(rid))
                    {
                        agree++;
                        if (inbound_sources.contains(other))
                            inbound_agrees = true;
                    }

                if (agree < needed)
                    continue;

                if (not inbound_agrees)
                {
                    log::info(
                        logcat,
                        "{} sources know RouterID {}, but none of them is one of ours; not accepting it",
                        agree,
                        rid);
                    continue;
                }

                accepted.insert(rid);
            }
        }

        // Whether the sources disagreed or simply did not answer, the outcome is the same: we have
        // no consensus to act on.  We got the list we already have from somewhere, and had reason to
        // trust it, so it stands until a consensus replaces it.
        if (accepted.empty())
        {
            log::warning(
                logcat,
                "No consensus from {} RouterID sources; keeping the {} RouterIDs we already have",
                asked,
                known_rids.size());
            return false;
        }

        known_rids = std::move(accepted);

        fetch_rcs();
        return true;
    }

    void NodeDB::start()
    {
        log::trace(logcat, "NodeDB starting timers...");

        _purge_timer = _router._jq->add_timer(PURGE_INTERVAL, [this] { purge_rcs(); });

        auto need_bootstrap = num_rcs() < MIN_ACTIVE_RCS;
        if (not has_bootstraps())
        {
            log::warning(logcat, "Only {} known RCs, but no bootstrap nodes are configured", num_rcs());
            need_bootstrap = false;
        }

        if (not _router.is_service_node)
        {
            _router._jq->call_later(100ms, [this] { fetch_rids(); });
        }

        _0rtt_saver = _router.disk_jq.add_wakeable([this] { _0rtt_save(); });
        _router.disk_jq.wake(_0rtt_saver);

        if (need_bootstrap)
            bootstrap();
    }

    void NodeDB::on_bootstrap_done(bool success)
    {
        // This attempt is over either way; without clearing it the guard in purge_rcs() stays shut
        // for the life of the process, and a client that loses its relays can never bootstrap again.
        _bootstrap_running = false;

        if (success)
        {
            log::debug(logcat, "Bootstrap attempt completed successfully");
            _bootstrap_fails = 0;
        }
        else
        {
            _bootstrap_fails++;
            log::debug(logcat, "Bootstrap attempt failed ({} consecutive failures)", _bootstrap_fails);
        }

        if (num_rcs() >= MIN_ACTIVE_RCS)
            return;

        auto cooldown = std::min(BOOTSTRAP_COOLDOWN * (success ? 1 : _bootstrap_fails), BOOTSTRAP_COOLDOWN_MAX);
        log::warning(
            logcat,
            "Not enough RCs ({}) after {} bootstrap attempt; trying again in {}",
            num_rcs(),
            success ? "successful" : "failed",
            cooldown);
        _router._jq->call_later(cooldown, [this] { bootstrap(); });
    }

    NodeDB::NodeDB(Router& r) : _router{r}, _root{_router.config().router.data_dir / nodedb_dirname}
    {
        if (not exists(_root))
            create_directory(_root);
        if (not is_directory(_root))
            throw std::runtime_error{fmt::format("nodedb {} is not a directory", _root)};

        load_bootstraps();

        load_from_disk();

        if (_router.is_service_node)
        {
            // Make self.signed a symlink to the full ID.signed file.  (The full file might not
            // exist if we aren't a relay, but that's okay: we intentionally leave a dangling
            // symlink in that case).
            auto self_signed = _root / our_rc_filename;
            std::error_code ec;  // Ignore errors on the below as this is just for convenience but
                                 // doesn't otherwise matter.
            remove(self_signed, ec);
            create_symlink(
                std::filesystem::path{_router.id().to_string()}.replace_extension(RC_FILE_EXT), self_signed, ec);
        }
    }

    void NodeDB::load_bootstrap(const std::filesystem::path& fpath)
    {
        if (not exists(fpath))
            throw std::runtime_error{"Bootstrap RC file '{}' does not exist"_format(fpath)};

        auto content = util::file_to_string(fpath);
        if (content.empty())
            throw std::runtime_error{"Bootstrap RC file '{}' is empty"_format(fpath)};

        load_bootstrap(content, "Bootstrap RC file '{}'"_format(fpath));

        log::debug(logcat, "Successfully loaded BootstrapRC file {} ({}B)", fpath, content.size());
    }

    void NodeDB::load_bootstrap(std::string_view data, std::string_view input_desc)
    {
        try
        {
            // Bootstrap data can container either a list of bootstraps, or just a single bootstrap RC:
            if (data.front() == 'l')
            {
                // list of bootstrap RCs
                for (oxenc::bt_list_consumer l{data}; !l.is_finished();)
                    _bootstraps.emplace_back(l.consume_dict_data(), _router.netid(), /*accept_expired=*/true);
            }
            else
            {
                // single bootstrap RC
                _bootstraps.emplace_back(data, _router.netid(), /*accept_expired=*/true);
            }
        }
        catch (const std::exception& e)
        {
            log::debug(
                logcat, "Failed to load the following bootstrap data from {}: {}", input_desc, buffer_printer{data});
            throw std::runtime_error{"{} does not contain valid bootstrap data: {}"_format(input_desc, e.what())};
        }
    }

    void NodeDB::load_bootstraps()
    {
        const auto def = _router.config().router.data_dir / default_bootstrap;
        for (const auto& f : _router.config().bootstrap.files)
        {
            log::debug(logcat, "Loading BootstrapRC from file {}", f);
            load_bootstrap(f);
        }

        if (_router.config().bootstrap.files.empty() && exists(def))
        {
            log::debug(logcat, "No configured bootstraps; loading from {}", def);
            try
            {
                load_bootstrap(def);
            }
            catch (const std::exception& e)
            {
                log::warning(logcat, "Failed loading from default bootstrap file {}: {}.  Skipping it.", def, e.what());
            }
        }

        auto obsolete = std::erase_if(_bootstraps, [](const auto& bs) { return bs.is_obsolete(); });
        if (obsolete > 0)
            log::info(logcat, "Removed {} obsolete bootstraps RCs", obsolete);

        auto removed = std::erase_if(_bootstraps, [this](const auto& bs) { return bs.router_id() == _router.id(); });
        if (removed > 0)
            log::info(logcat, "Found and removed ourself ({}) from the bootstrap list", _router.id());

        if (_bootstraps.empty() && (removed > 0 || _router.config().bootstrap.files.empty()))
        {
            log::debug(logcat, "Bootstrap list is empty; loading built-in fallbacks");
            for (const auto& [n, rc_blob] : bootstrap_fallbacks)
            {
                if (n == _router.netid())
                {
                    load_bootstrap(rc_blob, "Fallback bootstrap data");
                    break;
                }
            }

            log::info(
                logcat,
                "Loaded {} {} default fallback bootstrap router contact(s)",
                _bootstraps.size(),
                _router.netid());

            if (_bootstraps.empty())
            {
                log::warning(
                    logcat,
                    "No bootstrap router contacts were loaded.  The default bootstrap file {} does not "
                    "exist, and this Session Router binary does not have any fallback bootstraps for the '{}' network.",
                    def,
                    _router.netid());
            }
        }

        std::shuffle(_bootstraps.begin(), _bootstraps.end(), srouter::csrng);

        log::debug(logcat, "We have {} Bootstrap router(s)!", _bootstraps.size());
    }

    void NodeDB::post_rid_fetch(bool shutdown)
    {
        assert(_router.loop().inside());
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        fetch_counter = 0;
        response_counter = 0;
        fail_counter = 0;
        fail_sources.clear();
        rid_result_counters.clear();

        if (shutdown)
        {
            log::warning(logcat, "Client stopped RouterID fetch without a sucessful response!");
        }
        else
            log::trace(logcat, "Client successfully completed RouterID fetch!");
    }

    bool NodeDB::handle_bootstrap_result(const RouterID& source, std::string_view body)
    {
        assert(_router.loop().inside());
        log::debug(logcat, "Received response to BootstrapRC fetch request...");

        int num = 0, n_stored = 0;

        try
        {
            oxenc::bt_dict_consumer btdc{body};

            auto compressed_rcs = btdc.require_span<std::byte>("Z");

            btdc.finish();

            zstd::decompressor decompressor;
            // 20M here is just a safety margin so that a malicious bootstrap can't feed us some
            // tiny data that decompresses into something that exhausts memory:
            auto rcs_data = zstd::decompressor{}.decompress(compressed_rcs, 20'000'000);
            if (!rcs_data)
                throw std::runtime_error{"Failed to decompress RC list"};

            oxenc::bt_list_consumer rclist{*rcs_data};

            while (not rclist.is_finished())
            {
                RelayContact new_rc{rclist.consume_dict_data(), _router.netid()};
                // if we're trusting the bootstrap for RCs regardless of RouterID, we
                // should trust the RouterID as well.
                known_rids.insert(new_rc.router_id());
                auto [stored, gossip] = put_rc(std::move(new_rc));
                n_stored += stored;
                ++num;
            }
        }
        catch (const std::exception& e)
        {
            log::warning(
                logcat, "Failed to parse BootstrapRC fetch response from {}: {}", source.short_string(), e.what());
            return false;
        }

        log::info(logcat, "Bootstrap fetch successfully retrieved {} RCs ({} stored)", num, n_stored);
        return true;
    }

    bool NodeDB::has_registered_relays() const
    {
        std::shared_lock lock{_registered_relays_mutex};
        return not _registered_relays.empty();
    }

    void NodeDB::set_registered_relays(std::unordered_set<RouterID> relays)
    {
        log::debug(logcat, "Oxend provided {} whitelisted routers", relays.size());

        if (relays.empty())
            return;

        size_t size = relays.size();
        {
            std::unique_lock lock{_registered_relays_mutex};
            std::swap(relays, _registered_relays);
        }

        if (relays.empty())
            log::info(logcat, "Loaded initial SN list from oxend with {} registered relays", size);
        else
            log::debug(logcat, "Updated SN list from oxend with {} registered relays", size);
    }

    void NodeDB::load_registered_relays_fallback()
    {
        std::unique_lock lock{_registered_relays_mutex};

        if (not _registered_relays.empty())
        {
            // Perhaps a race with a result fetch?
            log::debug(logcat, "Not loading registered relay fallback: we already have registered relays");
            return;
        }

        auto now = srouter::time_now_ms();
        for (auto& [rid, rc] : known_rcs)
            if (!rc.is_expired(now))
                _registered_relays.insert(rid);
    }

    std::vector<RouterID> NodeDB::get_registered_relays() const
    {
        std::vector<RouterID> result;
        std::shared_lock lock{_registered_relays_mutex};
        result.reserve(_registered_relays.size());
        result.assign(_registered_relays.begin(), _registered_relays.end());

        return result;
    }

    std::unordered_set<RouterID> NodeDB::get_registered_relay_set() const
    {
        std::shared_lock lock{_registered_relays_mutex};
        std::unordered_set<RouterID> result{_registered_relays};
        return result;
    }

    bool NodeDB::is_registered(const RouterID& relay) const
    {
        std::shared_lock lock{_registered_relays_mutex};
        return _registered_relays.contains(relay);
    }

    std::optional<RouterID> NodeDB::get_random_registered_relay() const
    {
        std::optional<RouterID> result;
        std::shared_lock lock{_registered_relays_mutex};
        if (!_registered_relays.empty())
            result = *std::next(
                _registered_relays.begin(),
                std::uniform_int_distribution<int>{0, static_cast<int>(_registered_relays.size())}(srouter::csrng));
        return result;
    }

    void NodeDB::load_from_disk()
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_root.empty())
            return;

        std::vector<std::filesystem::path> purge;

        const auto now = time_now_ms();
        const auto real_now = std::chrono::system_clock::now();

        for (const auto& f : std::filesystem::directory_iterator{_root})
        {
            if (not f.is_regular_file())
                continue;

            RouterID filename_rid;
            // Ignoring anything that doesn't look like PUBKEY.ext:
            if (auto no_ext = f.path().stem().u8string(); no_ext.size() == oxenc::to_base32z_size(RouterID::SIZE)
                and oxenc::is_base32z(no_ext.begin(), no_ext.end()))
            {
                oxenc::from_base32z(no_ext.begin(), no_ext.end(), filename_rid.begin());
            }
            else
            {
                log::debug(logcat, "Skipping {}: does not match PUBKEY.(ext) filename format", f.path());
                continue;
            }

            auto ext = f.path().extension();
            if (ext == RC_FILE_EXT)
            {
                std::optional<RelayContact> rc;
                try
                {
                    rc.emplace(f.path(), _router.netid());
                }
                catch (const std::exception& e)
                {
                    log::warning(logcat, "Failed to load {} from stored RCs: {}", f.path(), e.what());
                }

                if (not rc or rc->is_expired(now))
                {
                    // try loading it, purge it if it is junk or expired
                    purge.push_back(f);
                    continue;
                }

                auto rid = rc->router_id();

                if (rid != filename_rid)
                {
                    log::error(
                        logcat,
                        "Invalid stored RC: RC contains pubkey {} which does not match filename {}",
                        rid,
                        f.path());
                    purge.push_back(f);
                    continue;
                }

                if (not _router.is_service_node)
                    known_rids.insert(rid);  // Only clients use this container
                known_rcs.emplace(std::move(rid), std::move(*rc));
            }
            else if (ext == ZRTT_FILE_EXT)
            {
                std::string content;
                try
                {
                    content = util::file_to_string(f.path());
                    oxenc::bt_dict_consumer top{content};
                    RouterID rid{top.require_span<std::byte, RouterID::SIZE>("@")};
                    if (rid != filename_rid)
                        throw std::runtime_error{"pubkey {} does not match filename {}"_format(rid, f.path())};

                    if (top.skip_until("R"))
                    {
                        if (!_router.is_service_node)
                            throw std::runtime_error{"ticket is for a relay but we are a client"};

                        RouterID check_rid{top.consume_span<std::byte, RouterID::SIZE>()};
                        if (check_rid != _router.id())
                            throw std::runtime_error{"ticket is for a different relay"};
                    }
                    else if (_router.is_service_node)
                        throw std::runtime_error{"ticket is for a client but we are a relay"};

                    std::list<std::pair<std::vector<unsigned char>, std::chrono::sys_seconds>> tickets;
                    auto recs = top.consume_list_consumer();
                    while (!recs.is_finished())
                    {
                        auto rec = recs.consume_dict_consumer();
                        auto data_sp = rec.require_span<unsigned char>("d");
                        std::vector<unsigned char> data{data_sp.begin(), data_sp.end()};
                        std::chrono::sys_seconds expiry{std::chrono::seconds{rec.require<int64_t>("e")}};
                        if (expiry > real_now)
                            tickets.emplace_back(std::move(data), expiry);
                        rec.finish();
                    }
                    top.finish();

                    if (tickets.empty())
                    {
                        // Everything expired
                        log::debug(logcat, "Deleting 0RTT ticket file {}: no unexpired tickets found", f.path());
                        purge.push_back(f);
                        continue;
                    }
                    _0rtt_tickets[rid] = std::move(tickets);
                }
                catch (const std::exception& e)
                {
                    log::warning(
                        logcat, "Failed to load {} from stored 0RTT data: {}; deleting it.", f.path(), e.what());
                    purge.push_back(f);
                    continue;
                }
            }
            else
                log::trace(logcat, "Skipping file with unknown extension: {}", f.path());
        }

        if (not purge.empty())
        {
            log::info(logcat, "removing {} invalid or expired RC/0RTT files from disk", purge.size());
            for (const auto& fpath : purge)
                remove(fpath);
        }

        // initialize rc fetch buckets
        for (const auto& [rid, rc] : known_rcs)
        {
            update_rc_buckets(rc, /*added=*/true);
        }

        log::info(
            logcat, "Loaded {} RCs + 0-RTT tickets for {} relays from disk", known_rcs.size(), _0rtt_tickets.size());
    }

    void NodeDB::cleanup()
    {
        if (_purge_timer)
        {
            log::trace(logcat, "NodeDB clearing purge timer...");
            _router._jq->remove(_purge_timer);
            _purge_timer = {};
        }

        if (_0rtt_saver)
        {
            // Removing cancels any wake that hasn't run yet, so flush first or we drop the tickets
            // it was woken for.  This must not hold _0rtt_mutex: removing from off the disk loop
            // waits for a running _0rtt_save(), which wants that lock.
            log::trace(logcat, "NodeDB flushing 0-RTT tickets...");
            _0rtt_save();
            _router.disk_jq.remove(_0rtt_saver);
            _0rtt_saver = {};
        }

        log::debug(logcat, "NodeDB cleared all timers...");
    }

    const RelayContact* NodeDB::get_rc(const RouterID& pk) const
    {
        assert(_router.loop().inside());
        auto it = known_rcs.find(pk);
        return it != known_rcs.end() ? &it->second : nullptr;
    }

    std::pair<bool, bool> NodeDB::put_rc(RelayContact rc)
    {
        assert(_router.loop().inside());

        const auto& rid = rc.router_id();

        auto [it, new_rc] = known_rcs.try_emplace(rid, std::move(rc));
        auto& stored = it->second;

        bool should_gossip, significant_change;
        if (new_rc)
        {
            // If this is a brand new RC then we want to gossip it to make sure everyone gets it.
            should_gossip = significant_change = true;
        }
        else if (!rc.newer_than(stored, RelayContact::MIN_GOSSIP_RC_AGE))
        {
            // The RC is too new since the last one we stored, so drop it.
            return {false, false};
        }
        else
        {
            // This RC is an update of one we already have: we only gossip if this RC is a
            // significant change (e.g. a port, IP or version change) or was the first RC from this
            // node in a long time, both of which are updates we want to waste a little extra network
            // bandwidth for to get out everywhere ASAP via gossipping.  Otherwise it's a mundane
            // update, and so we don't gossip it because the full-mesh network connections means it
            // will send it directly to everyone (and other nodes don't need to update to be able to
            // full mesh with it).
            //
            // The bucket hash is what defines "significant": it covers everything identifying the
            // relay and deliberately excludes the timestamp and signature, which is exactly the
            // mundane/significant distinction we want here.
            //
            // For our own RC, we always gossip if we get here because we always want to tell our
            // peers when we update our *own* RC.
            significant_change = bucket_hash(rc.view()) != bucket_hash(stored.view());
            should_gossip = rc.router_id() == _router.id() || rc.newer_than(stored, RelayContact::OUTDATED_AGE)
                || significant_change;
            stored = std::move(rc);
        }

        if (significant_change)
            update_rc_buckets(stored, /*added=*/true);

        // We inserted or updated the record, so queue saving it to disk on the disk loop
        _router.disk_loop.call_soon([rc = stored, path = get_path_by_pubkey(stored.router_id())] { rc.write(path); });

        // Gossipping is a relay's job: a client stores RCs but has nobody to rebroadcast them to.
        return {true, should_gossip and _router.is_service_node};
    }

    std::pair<bool, bool> NodeDB::verify_store_gossip_rc(RelayContact rc)
    {
        assert(_router.loop().inside());
        if (not is_registered(rc.router_id()) || rc.router_id() == _router.id())
            return {false, false};
        return put_rc(std::move(rc));
    }

    int NodeDB::num_rcs(bool include_self) const
    {
        assert(_router.loop().inside());
        int total = static_cast<int>(known_rcs.size());
        if (not include_self and _router.is_service_node and known_rcs.contains(_router.id()))
            --total;
        return total;
    }

    int NodeDB::num_rids() const
    {
        assert(_router.loop().inside());
        if (_router.is_service_node)
        {
            std::shared_lock lock{_registered_relays_mutex};
            return static_cast<int>(_registered_relays.size());
        }
        return static_cast<int>(known_rids.size());
    }

    void NodeDB::remove_rcs_if(const std::function<bool(const RelayContact&)>& remove)
    {
        assert(_router.loop().inside());

        std::vector<RouterID> removed;

        for (auto it = known_rcs.begin(); it != known_rcs.end();)
        {
            const auto& [rid, rc] = *it;
            if (remove(rc))
            {
                removed.push_back(rid);
                update_rc_buckets(rc, /*added=*/false);
                it = known_rcs.erase(it);
            }
            else
                ++it;
        }

        if (not removed.empty())
            remove_many_from_disk_async(std::move(removed));
    }

    void NodeDB::remove_many_from_disk_async(const std::vector<RouterID>& remove) const
    {
        assert(_router.loop().inside());
        if (_root.empty())
            return;

        // build file list
        std::vector<std::filesystem::path> files;
        files.reserve(remove.size());
        for (const auto& rid : remove)
            files.push_back(get_path_by_pubkey(rid));

        // remove them from the disk via the diskio thread
        _router.disk_loop.call_soon([files = std::move(files)] {
            for (const auto& p : files)
                std::filesystem::remove(p);
        });
    }

    namespace
    {
        inline uint64_t xor_condense(const AlignedBuffer<32>& x)
        {
            auto* y = reinterpret_cast<const uint64_t*>(x.data());
            return y[0] ^ y[1] ^ y[2] ^ y[3];
        }

        // Metric for determining the "closest" router ID to a given blinded pubkey, used for
        // blinded CC publishing.
        //
        // This consists of xoring all of the uint64_t chunks of the blinded pubkey with the router
        // ID and returning the smallest value.
        struct PublishLocationMetric
        {
            PublishLocationMetric(const PubKey& blinded_pk) : pk_xor{xor_condense(blinded_pk)} {}

            const uint64_t pk_xor;  // xor of the blinded PK
            bool operator()(const RouterID* left, const RouterID* right) const
            {
                auto l = xor_condense(*left) ^ pk_xor;
                auto r = xor_condense(*right) ^ pk_xor;
                return std::tie(l, *left) < std::tie(r, *right);
            }
        };
    }  // namespace

    std::vector<RouterID> NodeDB::find_many_closest_to(const PubKey& blinded_pk, int num_routers) const
    {
        assert(_router.loop().inside());
        if (num_routers <= 0)
            return {};

        std::shared_lock lock{_registered_relays_mutex};
        auto rr = _registered_relays | std::views::transform([](const auto& rid) { return &rid; });
        std::vector<const RouterID*> rids{rr.begin(), rr.end()};
        num_routers = std::min(num_routers, static_cast<int>(rids.size()));
        std::ranges::partial_sort(rids, rids.begin() + num_routers, PublishLocationMetric{blinded_pk});
        rids.resize(num_routers);
        std::vector<RouterID> result;
        result.reserve(rids.size());
        for (auto* rid : rids)
            result.push_back(*rid);
        return result;
    }

    void NodeDB::store_0rtt(const RouterID& rid, std::vector<unsigned char> data, std::chrono::sys_seconds expiry)
    {
        std::lock_guard lock{_0rtt_mutex};
        auto& tickets = _0rtt_tickets[rid];
        while (tickets.size() >= MAX_0RTT_TICKETS)
            tickets.pop_front();
        tickets.emplace_back(std::move(data), expiry);
        _0rtt_dirty.insert(rid);
        // The gnutls 0-RTT callbacks that reach here fire off the quic endpoint, which outlives
        // cleanup(), so the saver may already be gone; waking a timer that no longer exists throws.
        if (_0rtt_saver)
            _router.disk_jq.wake(_0rtt_saver);
    }

    std::optional<std::vector<unsigned char>> NodeDB::extract_0rtt(const RouterID& rid)
    {
        std::lock_guard lock{_0rtt_mutex};
        std::optional<std::vector<unsigned char>> ret;
        auto now = std::chrono::system_clock::now();
        auto it = _0rtt_tickets.find(rid);
        if (it != _0rtt_tickets.end())
        {
            auto& tickets = it->second;
            // Delete any expired tickets:
            while (!tickets.empty() && tickets.front().second < now)
                tickets.pop_front();
            if (!tickets.empty())
            {
                ret = std::move(tickets.front().first);
                tickets.pop_front();
            }
            _0rtt_dirty.insert(rid);
            if (_0rtt_saver)
                _router.disk_jq.wake(_0rtt_saver);
        }
        return ret;
    }

    void NodeDB::_0rtt_save()
    {
        std::list<std::pair<std::filesystem::path, std::string>> rewrite;
        std::list<std::filesystem::path> erase;

        {
            std::lock_guard lock{_0rtt_mutex};
            auto now = std::chrono::system_clock::now();
            for (const auto& rid : _0rtt_dirty)
            {
                auto path = get_path_by_pubkey(rid, ZRTT_FILE_EXT);
                auto it = _0rtt_tickets.find(rid);
                if (it == _0rtt_tickets.end())
                    erase.push_back(std::move(path));
                else
                {
                    auto& tickets = it->second;
                    // Delete any expired tickets:
                    while (!tickets.empty() && tickets.front().second < now)
                        tickets.pop_front();

                    if (!tickets.empty())
                    {
                        oxenc::bt_dict_producer top;
                        // Target relay RID, for verification that this is actually connecting to
                        // the expected place:
                        top.append("@", rid.span());

                        // If *we* are a relay then record our own pubkey here (and otherwise
                        // don't), so that when loading we refuse to load a file that doesn't match
                        // our pubkey and/or relay state, just in case someone copies the nodedb
                        // with tickets in it from one data dir to another.
                        if (_router.is_service_node)
                            top.append("R", _router.id().to_view());

                        auto recs = top.append_list("r");
                        for (const auto& [data, exp] : tickets)
                        {
                            auto e = recs.append_dict();
                            e.append("d", std::span{reinterpret_cast<const std::byte*>(data.data()), data.size()});
                            e.append("e", exp.time_since_epoch().count());
                        }
                        rewrite.emplace_back(std::move(path), std::move(top).str());
                        ++it;
                    }
                    else
                    {
                        erase.push_back(std::move(path));
                        it = _0rtt_tickets.erase(it);
                    }
                }
            }
            _0rtt_dirty.clear();
        }

        for (const auto& path : erase)
        {
            try
            {
                std::filesystem::remove(path);
            }
            catch (const std::exception& e)
            {
                log::error(logcat, "Failed to remove expired 0RTT ticket file {}: {}", path, e.what());
            }
        }
        for (const auto& [path, data] : rewrite)
        {
            try
            {
                util::buffer_to_file(path, data);
            }
            catch (const std::exception& e)
            {
                log::error(logcat, "Failed to update 0RTT ticket file {}: {}", path, e.what());
            }
        }
    }

}  // namespace srouter
