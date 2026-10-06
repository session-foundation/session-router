#include "contactdb.hpp"

#include "constants/path.hpp"
#include "router/router.hpp"
#include "util/logging/buffer.hpp"

#include <oxenc/bt_serialize.h>

namespace srouter
{
    static auto logcat = log::Cat("contactdb");

    ContactDB::ContactDB(Router& r) : _router{r} {}

    std::optional<std::string_view> ContactDB::get_encrypted_cc(
        const PubKey& blinded_key, std::optional<sys_ms> now) const
    {
        auto it = _storage.find(blinded_key);
        if (it == _storage.end())
            return std::nullopt;
        const auto& [record, signed_at] = it->second;
        if (now.value_or(time_now_ms()) >= signed_at + path::MAX_LIFETIME_ACCEPTED)
            return std::nullopt;
        return std::make_optional<std::string_view>(record);
    }

    size_t ContactDB::num_ccs() const { return _storage.size(); }

    void ContactDB::start_timers()
    {
        _purge_timer = _router._jq->add_timer(30s, [this]() { purge_ccs(); });
    }

    void ContactDB::purge_ccs(sys_ms now)
    {
        log::trace(logcat, "{} called", __PRETTY_FUNCTION__);

        if (_router.is_stopping() || not _router.is_running())
        {
            log::debug(logcat, "ContactDB unable to continue purge ticking -- router is stopped!");
            return;
        }

        size_t removed = std::erase_if(
            _storage, [&now](const auto& c) { return now > c.second.second + path::MAX_LIFETIME_ACCEPTED; });
        if (removed)
            log::debug(logcat, "{} expired ClientContacts purged, {} remaining", removed, _storage.size());
        else
            log::trace(logcat, "No ClientContacts current expired (of {})", _storage.size());
    }

    bool ContactDB::put_cc(std::string enccc)
    {
        std::pair<std::string, sys_ms> value{std::move(enccc), {}};
        auto& [payload, signed_at] = value;
        PubKey blinded_pk;

        auto it = _storage.end();
        bool ins = false;

        try
        {
            oxenc::bt_dict_consumer btdc{payload};

            blinded_pk.assign(btdc.require_span<std::byte, PubKey::SIZE>("i"));

            // It has to have a nonce, but we don't care about it:
            btdc.require_span<std::byte, SymmNonce::SIZE>("n");

            signed_at = sys_ms{std::chrono::milliseconds{btdc.require<int64_t>("t")}};

            // Attempt to insert a stub value so that we can short-circuit the signature parsing
            // below if this is a stale record, and otherwise fill in the stub if everything checks
            // out.
            std::tie(it, ins) = _storage.try_emplace(blinded_pk);
            if (!ins && it->second.second >= signed_at)
                // We already have a verified entry with a newer signed at, then just drop this one.
                return false;

            // We don't care about the encrypted value, either (aside from requiring it is here)
            btdc.require_span<std::byte>("x");

            btdc.require_signature("~", [blinded_pk](std::span<const std::byte> m, std::span<const std::byte> s) {
                if (s.size() != Signature::SIZE)
                    throw std::runtime_error{"Invalid signature: not 64 bytes"};

                if (not blinded_pk.verify(m, SignatureView{s.first<Signature::SIZE>()}))
                    throw std::runtime_error{"Encrypted client contact signature verification failed"};
            });

            it->second = std::move(value);
            return true;
        }
        catch (const std::exception& e)
        {
            log::warning(logcat, "Encrypted client contact deserialization failed: {}", e.what());
            log::trace(logcat, "Failing Encrypted CC data: {}", buffer_printer{payload});

            // If we inserted a stub, erase it:
            if (ins)
                _storage.erase(it);

            throw;
        }
    }

}  //  namespace srouter
