#include "config/config.hpp"
#include "constants/version.hpp"
#include "crypto/crypto.hpp"
#include "link/link_manager.hpp"
#include "router/router.hpp"
#include "util/logging.hpp"
#include "util/service_manager.hpp"

#include <oxen/quic/loop.hpp>
#include <session/router_context.hpp>

#include <csignal>
#include <memory>
#include <stdexcept>

#if (__FreeBSD__) || (__OpenBSD__) || (__NetBSD__)
#include <pthread_np.h>
#endif

namespace srouter
{
    static auto logcat = log::Cat("context");

    bool Context::looks_alive() const { return router->looks_alive(); }

    bool Context::is_running() const { return running.load(); }

    void Context::wait() { lifetime_waiter.get(); }

    void Context::start(Config conf, std::shared_ptr<oxen::quic::Loop> loop)
    {
        if (router)
        {
            log::error(logcat, "Context::start called but Session Router is already running");
            throw std::logic_error{"Session Router is already started"};
        }
        if (loop)
            log::debug(logcat, "Re-using existing loop");
        else
        {
            log::debug(logcat, "Initializing event loop...");

            loop = std::make_shared<quic::Loop>();
            assert(loop->call_get([] { return 42; }) == 42);

            log::debug(logcat, "Event loop initialized!");
        }
        router_loop = loop;

        std::promise<void> done_promise;
        lifetime_waiter = done_promise.get_future();

        std::shared_ptr<srouter::vpn::Platform> plat;
        if (!embedded)
        {
            log::debug(logcat, "Initializing platform code...");
            if (vpn::make_native_platform)
                plat = vpn::make_native_platform(this);
            if (!plat)
                throw std::runtime_error{"This platform is not currently supported!"};
        }

        log::debug(logcat, "Starting main router...");
        try
        {
            router = new Router{std::move(conf), loop, std::move(plat), std::move(done_promise)};
        }
        catch (const std::exception& e)
        {
            log::error(logcat, "Failed to initialize router: {}", e.what());
            throw;
        }
    }

    void Context::stop()
    {
        if (!running.exchange(false))
            return;

        router->stop();
    }

    Context::~Context()
    {
        // if stop() has not been called yet, we wait on the future.  If something else calls stop,
        // it is expected to wait on the future.
        if (running.exchange(false))
        {
            router->stop();
            wait();
        }

        router_loop->call_get([this]() { delete router; });
    }

    void Context::signal(int sig)
    {
        if (router && (sig == SIGINT || sig == SIGTERM || sig == SIGKILL))
        {
            log::warning(
                logcat,
                "Received signal SIG{}; stopping router...",
                sig == SIGINT        ? "INT"
                    : sig == SIGTERM ? "TERM"
                                     : "KILL");
            stop();
        }
    }

    Context::Context(bool embedded, Config conf, std::shared_ptr<oxen::quic::Loop> loop) : embedded{embedded}
    {
        // service_manager is a global and context isnt
        if (!embedded)
            srouter::sys::service_manager->give_context(this);
        start(std::move(conf), std::move(loop));
    }

}  // namespace srouter
