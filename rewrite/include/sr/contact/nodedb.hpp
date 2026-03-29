#pragma once

#include <sr/contact/relay_contact.hpp>
#include <sr/contact/router_id.hpp>
#include <sr/crypto/dh.hpp>

#include <chrono>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace sr::contact
{

    // NodeDB manages the routing table: known relay contacts, bootstrap,
    // bucket hashing for incremental sync, and hop selection for path building.

    class NodeDB
    {
      public:
        NodeDB() = default;

        // Store a relay contact (verified externally before calling this)
        bool put_rc(const RelayContact& rc);

        // Remove a relay contact
        void remove_rc(const RouterID& rid);

        // Lookup
        std::optional<RelayContact> get_rc(const RouterID& rid) const;
        bool has_rc(const RouterID& rid) const;

        // Get all known RouterIDs
        std::vector<RouterID> all_router_ids() const;

        // Get N random relay contacts for path building.
        // Excludes the given set (e.g., already-selected hops).
        std::vector<RelayContact> random_rcs(size_t count, const std::unordered_set<RouterID>& exclude = {}) const;

        // Purge expired RCs
        size_t purge_expired(std::chrono::system_clock::time_point now);

        // Bucket hashing for incremental RC sync.
        // 128 buckets, bucket index = byte 16 of RouterID & 0x7F.
        // Bucket hash = XOR of all RC hashes in that bucket.
        static constexpr size_t NUM_BUCKETS = 128;
        using BucketHashes = std::array<sr::crypto::Bytes<8>, NUM_BUCKETS>;

        BucketHashes compute_bucket_hashes() const;

        // Stats
        size_t size() const;
        bool has_min_rcs(size_t min = 6) const;

      private:
        mutable std::mutex _mtx;
        std::unordered_map<RouterID, RelayContact> _rcs;

        static size_t bucket_index(const RouterID& rid);
    };

}  // namespace sr::contact
