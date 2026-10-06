#pragma once

#include "contact/router_id.hpp"
#include "contact/sns.hpp"
#include "crypto/keys.hpp"

#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace srouter::rpc
{
    // Core-side interface for the oxend RPC client.  Router holds and drives an IOxendClient; the
    // concrete implementation (OxendRPC, which needs oxenmq) lives in the full rpc library and is
    // constructed via the full-only seam.  In embedded/core-only builds Router never constructs one
    // (the pointer stays null), so core references only this interface -- never oxenmq.
    struct IOxendClient
    {
        virtual ~IOxendClient() = default;

        virtual void start_pings() = 0;

        virtual Ed25519SecretKey obtain_identity_key() = 0;

        // Connect to oxend asynchronously.  Takes the address as a string (parsed into an
        // oxenmq::address by the implementation) so that oxenmq stays out of the core interface.
        virtual void connect_async(std::string url) = 0;

        virtual void update_service_node_list(std::shared_ptr<std::promise<void>> on_update = nullptr) = 0;

        virtual void inform_connection(RouterID router, bool success) = 0;

        virtual void lookup_sns_hash(
            std::string_view namehash,
            std::function<void(std::optional<std::pair<std::string, SymmNonce>>)> resultHandler) = 0;
    };

}  // namespace srouter::rpc
