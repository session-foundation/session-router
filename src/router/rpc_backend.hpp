#pragma once

#include <memory>

namespace oxenmq
{
    class OxenMQ;
}

namespace srouter
{
    class Router;
    namespace rpc
    {
        struct IOxendClient;
        class RPCServer;
    }  // namespace rpc
    namespace consensus
    {
        struct IReachability;
    }
    namespace handlers
    {
        struct ITunnel;
    }
    namespace dns
    {
        class Listener;
    }

    // Construction hooks for the full rpc/oxend/omq/reachability subsystem.  Installed once by
    // srouter::full::initialize() in full builds; left null in embedded/core-only builds (Router then
    // leaves the corresponding members null and never runs the relay/rpc code paths).
    //
    // Router continues to own and drive the constructed objects -- these hooks only build them, which
    // is what keeps oxenmq/rpc/reachability construction (and hence those dependencies) out of the
    // core library.
    struct RpcBackendHooks
    {
        std::shared_ptr<oxenmq::OxenMQ> (*make_omq)();
        void (*start_omq)(oxenmq::OxenMQ&);
        std::shared_ptr<rpc::IOxendClient> (*make_oxend)(Router&, oxenmq::OxenMQ&);
        std::shared_ptr<rpc::RPCServer> (*make_rpc_server)(Router&, oxenmq::OxenMQ&);
        std::shared_ptr<consensus::IReachability> (*make_reachability)(Router&);
        std::shared_ptr<handlers::ITunnel> (*make_tun)(Router&);
        std::shared_ptr<dns::Listener> (*make_dns)(Router&);
    };

    inline const RpcBackendHooks* rpc_backend = nullptr;

}  // namespace srouter
