#include <session/router.hpp>

#include <chrono>
#include <csignal>
#include <exception>
#include <filesystem>
#include <future>
#include <iostream>
#include <regex>

extern "C"
{
#include <unistd.h>
}

using namespace std::literals;

int main(int argc, char** argv)
{
    if (argc <= 1)
    {
        std::cerr << "USAGE: " << argv[0] << " {PUBKEY.sesh | PUBKEY.snode | ONS.loki}[:REMOTEPORT]\n";
        return 1;
    }

    // Block signal handling by default from all threads, so that we handle signals exclusively in
    // this main thread below.
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    for (auto sig : {SIGINT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2})
        sigaddset(&signal_mask, sig);
    pthread_sigmask(SIG_BLOCK, &signal_mask, nullptr);

    std::string target{argv[1]};

    int port = 12345; // Default, but updated if target ends with :PORT
    if (std::smatch m; std::regex_match(target, m, std::regex{"(.*):(\\d+)$"})) {
        port = std::stoi(m[2]);
        target = m[1];
    }

    auto srouter = std::make_unique<session::router::SessionRouter>(std::filesystem::path{"jank.ini"});

    std::promise<void> prom;
    std::promise<void> conn_prom;

    // Holding this is what keeps the tunnel up; dropping it releases it.
    session::router::udp_tunnel tunnel;

    bool first_conn = true;
    srouter->on_connected([&] {
        if (!first_conn)
            return;
        first_conn = false;
        std::cout << "\n\x1b[32;1mSession Router connected!\x1b[0m\n\n";
        conn_prom.set_value();
    });
    try
    {
        conn_prom.get_future().get();

        auto start = std::chrono::steady_clock::now();
        std::cout << "\x1b[33;1mINITIATING SESSION TO \x1b[34;1m" << target << "\x1b[0m\n\n" << std::flush;

        std::promise<std::string> resolve_prom;
        srouter->resolve(target, [&](std::optional<std::string> a, bool timeout) {
            if (a)
            {
                if (*a != target)
                {
                    auto now = std::chrono::steady_clock::now();
                    std::cout << "\n\n\x1b[35;1mRESOLVED SNS \x1b[34;1m" << target << "\x1b[35;1m TO \x1b[34;1m" << *a
                              << "\x1b[35;1m in " << std::chrono::round<std::chrono::milliseconds>(now - start).count()
                              << "ms\x1b[0m\n\n";
                    start = now;
                }
                resolve_prom.set_value(std::move(*a));
                return;
            }

            try
            {
                throw std::runtime_error{
                    "Failed to resolve ("s + (timeout ? "timeout" : "does not exist") + ") target \x1b[34;1m" + target};
            }
            catch (...)
            {
                resolve_prom.set_exception(std::current_exception());
            }
        });

        target = resolve_prom.get_future().get();

        tunnel = srouter->establish_udp(
            target,
            port,
            [&prom, &start, &port](auto udp_info) {
                std::cout
                    << "\n\x1b[32;1mSession established ("
                    << std::chrono::round<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
                    << "ms); remote UDP port " << port << " bound to local port [::1]:" << udp_info.local_port << "\x1b[0m\n\n"
                    << std::flush;
                prom.set_value();
            },
            [&prom](auto failure) {
                try
                {
                    throw std::runtime_error{
                        failure == session::router::tunnel_failure::unreachable ? "Remote is unreachable!"
                                                                               : "Session timed out!"};
                }
                catch (...)
                {
                    prom.set_exception(std::current_exception());
                }
            });

        prom.get_future().get();
        const auto current_path = srouter->get_path_for_session(target);
        if (!current_path)
        {
            std::cerr << "future returned with no session / no current path.\n";
            return 1;
        }
        size_t hop_count = 1;
        std::cout << "Path to snode:\n";
        for (const auto& [snode, ip] : current_path->hops)
        {
            std::cout << "\tHop " << hop_count << ":\t" << snode << " @ " << ip << "\n";
            hop_count++;
        }
        std::cout << "\tLatency: " << current_path->latency.count() << "ms, jitter: "
                  << current_path->jitter.count() << "us, pings: " << current_path->ping_responses
                  << " ok / " << current_path->ping_timeouts << " timed out ("
                  << current_path->ping_recent_timeouts << " in a row)\n"
                  << "\tExpires in "
                  << std::chrono::round<std::chrono::seconds>(
                         current_path->expiry - std::chrono::system_clock::now())
                         .count()
                  << "s\n";
    }
    catch (const std::exception& e)
    {
        std::cerr << "\n\n\x1b[31;1m" << e.what() << "\x1b[0m\n\n";
        return 1;
    }

    auto pid = getpid();
    std::cout << "\n\n\x1b[32;1mTunnel running.\n\n"
              << argv[0] << " signal controls:\n\n"
              << "    kill -SIGHUP " << pid << " -- close tunnels\n"
              << "    kill -SIGUSR1 " << pid << " -- re-open UDP tunnel\n"
              << "    kill -SIGUSR2 " << pid << " -- re-open TCP tunnel\n"
              << "    Ctrl-C -- shut down\x1b[0m\n\n\n";

    /*
    srouter.map_tcp_remote_port(std::string{argv[1]}, port,
        [&](auto tunnel_info) {
          std::cout << "\n\nTCP bound to port " << tunnel_info.local_port << "\n\n";
        },
        [&](auto error_str) {
          std::cerr << "\nTCP Tunnel map error: " << error_str << "\n";
        });
    */

    std::thread sig_thread{[&] {
        while (srouter)
        {
            int signo;
            sigwait(&signal_mask, &signo);
            switch (signo)
            {
                case SIGHUP:
                    std::cout << "\n\n\n\x1b[33;1mHangup signal received; closing UDP tunnel\x1b[0m\n\n\n";
                    tunnel.reset();
                    break;
                case SIGUSR1:
                {
                    std::cout << "\n\n\n\x1b[32;1mSIGUSR1 received: (re-)opening UDP tunnel\x1b[0m\n";
                    tunnel = srouter->establish_udp(target, port);
                    if (tunnel)
                        std::cout << "\n\x1b[32;1mUDP bound to port " << tunnel->local_port << "\x1b[0m\n\n";
                    else
                        std::cout << "\n\x1b[31;1m" << target << " is unreachable\x1b[0m\n\n";
                    break;
                }
                case SIGUSR2:
                    std::cout << "\n\x1b[31;1mSIGUSR2 received: TODO FIXME: reopen TCP tunnel\x1b[0m\n\n";
                    break;
                default:
                    std::cout << "\n\n\n\x1b[33;1mSignal " << signo << " received, shutting down\x1b\[0m\n\n\n";
                    srouter.reset();
                    break;
            }
        }
    }};
    sig_thread.join();
}
