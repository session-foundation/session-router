#pragma once

#include <future>
#include <memory>
#include <mutex>

namespace oxen::quic
{
    class Loop;
}

namespace srouter
{
    namespace vpn
    {
        class Platform;
    }

    struct Config;
    class Router;

    // Helper "context" that aids in starting up Session Router.
    //
    // Note that this class is *not* thread-safe: only one thread should attempt to hold and
    // interact with it to manage Session Router.
    //
    // TODO FIXME this class seems unnecessary, we should get rid of it.
    struct Context
    {
        Router* router = nullptr;

        explicit Context(bool embedded, Config conf, std::shared_ptr<oxen::quic::Loop> loop = nullptr);
        ~Context();

        // Call this to deliver a signal, such as SIGTERM or SIGINT to stop Session Router if currently
        // running.  (This can be called from any thread).
        void signal(int sig);

        // Anything calling this is responsible for not doing so during or after this object's destructor.
        bool looks_alive() const;

        bool is_running() const;

        // Blocks the current thread until the Router object has shut down.
        void wait();

        int androidFD = -1;

      private:
        // Starts Session Router; returns as soon as Session Router is up and running (or throws if startup
        // fails).  The loop may be provided in order to use an existing loop, but otherwise a new
        // one will be started.
        void start(Config conf, std::shared_ptr<oxen::quic::Loop> loop = nullptr);

        void stop();

        // We keep a copy of the event loop to ensure that it exists through the lifetime of Router
        std::shared_ptr<oxen::quic::Loop> router_loop;

        bool embedded;
        std::atomic<bool> running{true};
        std::future<void> lifetime_waiter;
    };
}  // namespace srouter
