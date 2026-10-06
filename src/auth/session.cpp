#include "session.hpp"

#include "crypto/key_manager.hpp"
#include "router/router.hpp"

namespace srouter::auth
{
    static auto logcat = log::Cat("auth_policy");

    SessionAuthPolicy::SessionAuthPolicy(Router& r, RouterID& remote, bool is_snode, bool is_exit)
        : AuthPolicy{r}, _is_snode_service{is_snode}, _is_exit_service{is_exit}, _remote{remote, not _is_snode_service}
    {
        // These can both be false but CANNOT both be true
        if (_is_exit_service and _is_snode_service)
            throw std::runtime_error{"Cannot create SessionAuthPolicy for a remote exit and remote service!"};

        if (_is_snode_service)
            _session_key = _router.secret_key();
        else
            _session_key = Ed25519SecretKey::generate();
    }

    std::optional<std::string_view> SessionAuthPolicy::fetch_auth_token()
    {
        std::optional<std::string_view> ret = std::nullopt;
        auto& exit_auths = _router.config().network.exit_auths;

        if (auto itr = exit_auths.find(_remote); itr != exit_auths.end())
            ret = itr->second;

        return ret;
    }

    bool SessionAuthPolicy::load_key_from_file(const char* fname)
    {
        try
        {
            KeyManager::load_from_file(_session_key, fname);
            return true;
        }
        catch (const std::exception& e)
        {
            log::error(logcat, "Failed to load secret key from {}: {}", fname, e.what());
        }
        return false;
    }

}  // namespace srouter::auth
