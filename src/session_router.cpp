#include "address/address.hpp"
#include "config/config.hpp"
#include "net/id.hpp"
#include "nodedb.hpp"
#include "router/router.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"

#include <oxenc/base32z.h>
#include <session/router.hpp>
#include <session/router_context.hpp>

#include <exception>
#include <future>
#include <stdexcept>

using namespace std::literals;

namespace
{
    static auto logcat = srouter::log::Cat("libsessionrouter");
}  // anonymous namespace

namespace session::router
{
    static auto make_embedded_context() { return std::make_unique<srouter::Context>(/*embedded=*/true); }

    SessionRouter::SessionRouter(std::string config, std::shared_ptr<oxen::quic::Loop> loop)
        : context{make_embedded_context()}
    {
        context->start(srouter::Config{srouter::config::Type::EmbeddedClient, std::move(config)}, loop);
    }

    SessionRouter::SessionRouter(path_ctor, const std::filesystem::path& config, std::shared_ptr<oxen::quic::Loop> loop)
        : context{make_embedded_context()}
    {
        ;
        context->start(srouter::Config{srouter::config::Type::EmbeddedClient, config}, loop);
    }

    SessionRouter::SessionRouter(Network n, std::shared_ptr<oxen::quic::Loop> loop) : context{make_embedded_context()}
    {
        srouter::Config conf{srouter::config::Type::EmbeddedClient};
        switch (n)
        {
            case Network::MAINNET:
                conf.router.net_id = srouter::NetID::MAINNET;
                break;
            case Network::TESTNET:
                conf.router.net_id = srouter::NetID::TESTNET;
                break;
            default:
                throw std::invalid_argument{"Unknown/unsupported network value passed to Session Router constructor"};
        }
        context->start(std::move(conf), loop);
    }

    SessionRouter::~SessionRouter()
    {
        context->stop();
        context->wait();
    }

    void SessionRouter::on_connected(std::function<void()> callback, bool persist)
    {
        context->router->on_connected(std::move(callback), persist);
    }

    void SessionRouter::on_disconnected(std::function<void()> callback, bool persist)
    {
        context->router->on_disconnected(std::move(callback), persist);
    }

    void SessionRouter::establish_udp(
        std::string_view remote,
        uint16_t port,
        std::function<void(tunnel_info info)> on_established,
        std::function<void(std::string errmsg)> failure)
    {
        // FIXME: check for valid ONS, and if so, we need to defer the lookup as well
        srouter::NetworkAddress netaddr;
        try
        {
            netaddr = srouter::NetworkAddress{remote};
        }
        catch (const std::exception& e)
        {
            failure("Invalid remote address: {}"_format(e.what()));
            return;
        }

        srouter::log::info(logcat, "Creating session for udp connection to {}", netaddr);
        context->router->session_endpoint().initiate_remote_session(
            netaddr,
            [&r = *context->router,
             port,
             netaddr,
             on_established = std::move(on_established),
             failure = std::move(failure)](srouter::session::Session& s) {
                if (!s.is_established())
                {
                    auto err = "Failed to establish remote session to {} for UDP tunnel[port={}]"_format(netaddr, port);
                    srouter::log::warning(logcat, "{}", err);
                    failure(std::move(err));
                    return;
                }

                // TODO FIXME: 1200 here is just a placeholder, we should be able to pick
                // something better!
                tunnel_info ti{.remote = netaddr.to_string(), .remote_port = port, .suggested_mtu = 1200};

                ti.local_port = s.setup_udp_mapping(port);
                srouter::log::info(
                    logcat,
                    "Session established to {}, with local port {} mapped to remote {}",
                    ti.remote,
                    ti.local_port,
                    ti.remote_port);

                on_established(std::move(ti));
            });
    }

    tunnel_info SessionRouter::establish_udp_blocking(std::string_view remote, uint16_t port)
    {
        std::promise<tunnel_info> prom;
        auto fut = prom.get_future();
        establish_udp(
            remote,
            port,
            [&prom](tunnel_info info) { prom.set_value(std::move(info)); },
            [&prom](std::string err) {
                try
                {
                    throw std::runtime_error{err};
                }
                catch (...)
                {
                    prom.set_exception(std::current_exception());
                }
            });

        return fut.get();
    }

    std::optional<snode_path> SessionRouter::get_path_for_session(std::string_view remote)
    {
        srouter::NetworkAddress netaddr;
        try
        {
            netaddr = srouter::NetworkAddress{remote};
        }
        catch (const std::exception& e)
        {
            srouter::log::info(logcat, "Invalid remote address: {}", e.what());
            return std::nullopt;
        }

        return context->router->loop.call_get([&r = context->router, addr = std::move(netaddr)]() {
            std::optional<snode_path> ret;
            if (auto s = r->session_endpoint().get_session(addr); s)
            {
                ret = s->current_path();
            }
            return ret;
        });
    }

    std::vector<session_path> SessionRouter::get_all_session_paths()
    {
        return context->router->loop.call_get([&r = context->router]() {
            std::vector<session_path> ret;
            auto f = [&ret](const srouter::NetworkAddress& addr, const srouter::session::Session& s) {
                ret.emplace_back(s.current_path(), addr.to_string());
            };
            return ret;
        });
    }

}  // namespace session::router
