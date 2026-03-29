#include <sr/contact/nodedb.hpp>

#include <sodium.h>

#include <algorithm>
#include <cstring>

namespace sr::contact
{

    using namespace sr::crypto;

    bool NodeDB::put_rc(const RelayContact& rc)
    {
        std::lock_guard lock{_mtx};
        auto [it, inserted] = _rcs.insert_or_assign(rc.router_id(), rc);
        return inserted;
    }

    void NodeDB::remove_rc(const RouterID& rid)
    {
        std::lock_guard lock{_mtx};
        _rcs.erase(rid);
    }

    std::optional<RelayContact> NodeDB::get_rc(const RouterID& rid) const
    {
        std::lock_guard lock{_mtx};
        auto it = _rcs.find(rid);
        if (it == _rcs.end())
            return std::nullopt;
        return it->second;
    }

    bool NodeDB::has_rc(const RouterID& rid) const
    {
        std::lock_guard lock{_mtx};
        return _rcs.contains(rid);
    }

    std::vector<RouterID> NodeDB::all_router_ids() const
    {
        std::lock_guard lock{_mtx};
        std::vector<RouterID> ids;
        ids.reserve(_rcs.size());
        for (const auto& [rid, _] : _rcs)
            ids.push_back(rid);
        return ids;
    }

    std::vector<RelayContact> NodeDB::random_rcs(size_t count, const std::unordered_set<RouterID>& exclude) const
    {
        std::lock_guard lock{_mtx};

        // Collect eligible RCs
        std::vector<const RelayContact*> eligible;
        for (const auto& [rid, rc] : _rcs)
        {
            if (!exclude.contains(rid))
                eligible.push_back(&rc);
        }

        // Reservoir sampling
        std::vector<RelayContact> result;
        result.reserve(std::min(count, eligible.size()));

        for (size_t i = 0; i < eligible.size(); ++i)
        {
            if (result.size() < count)
            {
                result.push_back(*eligible[i]);
            }
            else
            {
                // CSPRNG for anonymity-critical hop selection
                size_t j = randombytes_uniform(static_cast<uint32_t>(i + 1));
                if (j < count)
                    result[j] = *eligible[i];
            }
        }

        return result;
    }

    size_t NodeDB::purge_expired(std::chrono::system_clock::time_point now)
    {
        std::lock_guard lock{_mtx};
        size_t removed = 0;
        for (auto it = _rcs.begin(); it != _rcs.end();)
        {
            if (it->second.is_expired(now))
            {
                it = _rcs.erase(it);
                ++removed;
            }
            else
            {
                ++it;
            }
        }
        return removed;
    }

    size_t NodeDB::bucket_index(const RouterID& rid)
    {
        // Byte 16 of RouterID, masked to 7 bits (0-127)
        return static_cast<size_t>(static_cast<uint8_t>(rid.data()[16])) & 0x7F;
    }

    NodeDB::BucketHashes NodeDB::compute_bucket_hashes() const
    {
        std::lock_guard lock{_mtx};
        BucketHashes hashes{};

        for (const auto& [rid, rc] : _rcs)
        {
            size_t bucket = bucket_index(rid);
            // Hash the RC data
            auto rc_data = rc.to_bt_unsigned();
            auto h = short_hash(std::span<const std::byte>{rc_data});
            // XOR into bucket
            for (size_t i = 0; i < 8; ++i)
                hashes[bucket][i] ^= h[i];
        }

        return hashes;
    }

    size_t NodeDB::size() const
    {
        std::lock_guard lock{_mtx};
        return _rcs.size();
    }

    bool NodeDB::has_min_rcs(size_t min) const
    {
        std::lock_guard lock{_mtx};
        return _rcs.size() >= min;
    }

}  // namespace sr::contact
