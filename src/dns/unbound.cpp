#include "unbound.hpp"

#include "router/router.hpp"
#include "util/logging.hpp"
#include "util/try_calling.hpp"

#include <unbound-event.h>
#include <unbound.h>

namespace srouter::dns
{
    auto logcat = log::Cat("dns");

    void Unbound::ub_ctx_deleter::operator()(ub_ctx* ctx) { ub_ctx_delete(ctx); }

    Unbound::Unbound(Router& router) : _loop{*router._loop}
    {
        auto* ctx = ub_ctx_create_event(_loop.get_event_base());
        if (!ctx)
            throw std::runtime_error{"Failed to initialize unbound upstream DNS resolver"};

        _ctx.reset(ctx);

        auto& conf = router.config().dns;

        // Handler should not have constructed us if this isn't satisfied:
        assert(!conf._upstream_dns.empty());

        //  Tell unbound to set up and use internal threads for processing queries
        if (auto ret = ub_ctx_async(_ctx.get(), 1); ret != 0)
            throw std::runtime_error{"Failed to initialize unbound async mode: {}"_format(ub_strerror(ret))};

        for (auto& addr : conf._upstream_dns)
        {
            // libquic (as of v1.6.0) includes square brackets around the host() call for IPv6
            // addresses.  (Later versions should be fixed).  In case they are there, we need to
            // work around it by stripping them off before providing that value to unbound:
            auto h_maybe_brackets = addr.host();
            std::string_view h{h_maybe_brackets};
            if (h.starts_with('[') && h.ends_with(']'))
            {
                h.remove_prefix(1);
                h.remove_suffix(1);
            }
            auto str = "{}@{}"_format(h, addr.port());
            if (auto err = ub_ctx_set_fwd(ctx, str.c_str()))
                throw std::runtime_error{"Failed to configure {} as upstream dns: {}"_format(addr, ub_strerror(err))};
        }

        if (conf.unbound_hosts)
            if (int ret = ub_ctx_hosts(
                    ctx,
                    *conf.unbound_hosts == std::filesystem::path{"SYSTEM"} ? nullptr : conf.unbound_hosts->c_str());
                ret != 0)
                throw std::runtime_error{"Failed to register DNS hosts file: {}"_format(ub_strerror(ret))};

        for (auto& [opt, value] : conf.unbound_opts)
            if (auto ret = ub_ctx_set_option(_ctx.get(), opt.c_str(), value.c_str()); ret != 0)
                throw std::runtime_error{
                    "Failed to apply unbound option {} {}: {}"_format(opt, value, ub_strerror(ret))};
    }

    struct Unbound::active_query_state
    {
        Unbound* self;
        std::function<void(std::span<const std::byte>)> callback;
    };

    Unbound::~Unbound()
    {
        // Clean up any pending query callbacks:
        for (auto* st : _active_queries)
            delete st;
    }

    void Unbound::query(
        const std::string& name,
        RRType type,
        RRClass cls,
        std::function<void(std::span<const std::byte> response)> callback)
    {
        assert(_loop.inside());
        auto state = std::make_unique<active_query_state>(this, std::move(callback));

        int res = ub_resolve_event(
            _ctx.get(),
            name.c_str(),
            static_cast<int>(type),
            static_cast<int>(cls),
            state.get(),
            [](void* state_ptr,
               int /*rcode*/,
               void* packet,
               int packet_len,
               int /*sec*/,
               char* /*bogus*/,
               int /*ratelimited*/) {
                if (!state_ptr)
                    return;
                std::unique_ptr<active_query_state> state{static_cast<active_query_state*>(state_ptr)};
                state->self->_active_queries.erase(state.get());

                try_calling(
                    logcat,
                    state->callback,
                    std::span<const std::byte>{static_cast<const std::byte*>(packet), static_cast<size_t>(packet_len)});
            },
            nullptr /* async_id, which is only used for cancelling specific queries, which we don't do*/);

        if (res != 0)
        {
            log::warning(logcat, "Unbound failed to forward query: {}", ub_strerror(res));
            try_calling(logcat, state->callback, std::span<const std::byte>{});
            return;
        }

        _active_queries.insert(state.release());
    }

}  // namespace srouter::dns
