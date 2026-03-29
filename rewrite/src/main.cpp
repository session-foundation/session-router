#include <sr/node/node.hpp>

#include <atomic>
#include <csignal>
#include <iostream>

static std::atomic<bool> g_shutdown{false};

static void signal_handler([[maybe_unused]] int sig)
{
    // Only async-signal-safe operations here — set a flag, nothing else.
    g_shutdown.store(true, std::memory_order_relaxed);
}

int main(int argc, char** argv)
{
    try
    {
        auto config = sr::node::Config::from_args(argc, argv);

        sr::node::Node node{std::move(config)};

        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Poll the shutdown flag from main thread (safe to call stop() here)
        std::thread shutdown_watcher([&] {
            while (!g_shutdown.load(std::memory_order_relaxed))
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            std::cout << "\nShutting down...\n";
            node.stop();
        });

        node.run();

        if (shutdown_watcher.joinable())
            shutdown_watcher.join();

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
}
