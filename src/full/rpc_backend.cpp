#include "router/rpc_backend.hpp"

#include "consensus/reachability_testing.hpp"
#include "dns/listener.hpp"
#include "handlers/tun.hpp"
#include "router/router.hpp"
#include "rpc/oxend_rpc.hpp"
#include "rpc/rpc_server.hpp"
#include "util/logging.hpp"

#include <fmt/ranges.h>
#include <oxenmq/oxenmq.h>

#include <exception>
#include <memory>

namespace srouter::full
{
    static auto logcat = log::Cat("full");

    namespace
    {
        std::shared_ptr<oxenmq::OxenMQ> make_omq()
        {
            auto omq = std::make_shared<oxenmq::OxenMQ>();
            // Raise the max message size (no limit) so that syncing the registered relay list from
            // oxend -- which can exceed the default 1MB -- doesn't get the connection closed.
            omq->MAX_MSG_SIZE = -1;
            return omq;
        }

        void start_omq(oxenmq::OxenMQ& omq) { omq.start(); }

        std::shared_ptr<rpc::IOxendClient> make_oxend(Router& r, oxenmq::OxenMQ& omq)
        {
            return std::make_shared<rpc::OxendRPC>(omq, r);
        }

        std::shared_ptr<rpc::RPCServer> make_rpc_server(Router& r, oxenmq::OxenMQ& omq)
        {
            return std::make_shared<rpc::RPCServer>(omq, r);
        }

        std::shared_ptr<consensus::IReachability> make_reachability(Router& r)
        {
            return std::make_shared<consensus::reachability_testing>(r);
        }

        std::shared_ptr<handlers::ITunnel> make_tun(Router& r)
        {
            return r.loop().make_shared<handlers::TunEndpoint>(r);
        }

        std::shared_ptr<dns::Listener> make_dns(Router& r)
        {
            const auto& dns_bind = r.config().dns._listen_addrs;
            if (dns_bind.empty())
            {
                // Allowed (e.g. a service-only client), just unusual.
                log::warning(
                    logcat, "[dns]:listen is empty: DNS disabled.  Making outbound paths will not be possible");
                return nullptr;
            }

            std::shared_ptr<dns::Listener> listener;
            try
            {
                for (const auto& addr : dns_bind)
                {
                    if (!listener)
                        listener = r.loop().make_shared<dns::Listener>(r, addr);
                    else
                        listener->listen(r.loop(), addr);

                    log::info(logcat, "DNS listening on {} port {}", addr.host(), listener->last_port);
                }
            }
            catch (const std::exception& e)
            {
                log::error(logcat, "Failed to initialize DNS listener on {}: {}", fmt::join(dns_bind, ","), e.what());
                throw;
            }
            return listener;
        }

        const RpcBackendHooks hooks{
            .make_omq = &make_omq,
            .start_omq = &start_omq,
            .make_oxend = &make_oxend,
            .make_rpc_server = &make_rpc_server,
            .make_reachability = &make_reachability,
            .make_tun = &make_tun,
            .make_dns = &make_dns,
        };
    }  // namespace

    void install_rpc_backend() { rpc_backend = &hooks; }

}  // namespace srouter::full
