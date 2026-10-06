#pragma once

#include "client_contact.hpp"

#include <oxen/quic/timer_id.hpp>

#include <optional>

namespace srouter
{
    class Router;

    /// This class is used by relays to store blinded, encrypted client contacts pushed to relays by
    /// clients.
    ///
    /// Each client derives a blinded key at which to store their encrypted contact info, and
    /// publishes that to the "best" 4 locations, where "best" is the result of a hash involving the
    /// blinded pubkey and each router id.  On lookups, clients do the same, looking up a target
    /// pubkey by blinding it then requesting it from the 4 blinded locations.
    ///
    /// The 4-way storage is for redundancy against relays missing the publish, restarting, or
    /// shifts in node composition that could change which nodes are "best" as nodes get
    /// registered/deregistered.
    ///
    /// As a result of that redundance, we don't actually persist this records and instead merely
    /// hold them in memory (because if we restart, there are still 3 other nodes that should be
    /// able to provide it).
    class ContactDB
    {
      private:
        Router& _router;

        // blinded pubkey -> {record, signed_at}
        std::unordered_map<PubKey, std::pair<std::string, sys_ms>> _storage;

        quic::TimerID _purge_timer;

      public:
        explicit ContactDB(Router& r);

        std::optional<std::string_view> get_encrypted_cc(
            const PubKey& blinded_pk, std::optional<sys_ms> now = std::nullopt) const;

        // Attempts to parse and store the given encrypted client contact.  Returns true if stored
        // successfully, false if we already have the record (or a newer one for the same blinded
        // pubkey), and throws if we could not successfully parse it (or signature verification
        // failed).
        bool put_cc(std::string enc);

        void start_timers();

        size_t num_ccs() const;

      private:
        void purge_ccs(sys_ms now = srouter::time_now_ms());
    };

}  // namespace srouter
