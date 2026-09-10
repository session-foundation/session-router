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
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
}

using namespace std::literals;

static std::string_view failure_reason(session::router::tunnel_failure f)
{
    using session::router::tunnel_failure;
    switch (f)
    {
        case tunnel_failure::unreachable: return "remote is unreachable";
        case tunnel_failure::no_tcp: return "remote does not accept tunnelled TCP";
        case tunnel_failure::timeout: return "session timed out";
    }
    return "unknown failure";
}

// Connects to a mapped TCP port and makes a request on it, reporting how long the whole thing took.
// Used to exercise the promise that a connection made before the session is up is held rather than
// refused: it is called immediately after establish_tcp() returns, when the session cannot yet exist.
static void probe_tunnel(uint16_t local_port, std::string path)
{
    auto start = std::chrono::steady_clock::now();

    int fd = ::socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
    {
        std::cerr << "\n\x1b[31;1mprobe: socket() failed\x1b[0m\n";
        return;
    }

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(local_port);
    addr.sin6_addr = in6addr_loopback;

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        std::cerr << "\n\x1b[31;1mprobe: connect to [::1]:" << local_port << " failed\x1b[0m\n";
        ::close(fd);
        return;
    }

    auto req = "GET " + path + " HTTP/1.0\r\nHost: tunnel\r\n\r\n";
    ::send(fd, req.data(), req.size(), 0);

    std::string resp;
    char buf[4096];
    while (auto n = ::recv(fd, buf, sizeof(buf), 0))
    {
        if (n < 0)
            break;
        resp.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);

    auto ms = std::chrono::round<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    auto status = resp.substr(0, resp.find('\r'));
    std::cout << "\n\x1b[35;1mprobe: " << resp.size() << "B in " << ms << "ms -- " << status << "\x1b[0m\n\n"
              << std::flush;
}

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
    // Several comma-separated ports may be given, which maps each of them to the same remote; that
    // exercises multiple mappings sharing one session (and one tunnel connection).
    std::vector<uint16_t> tcp_ports;
    if (std::smatch m; std::regex_match(target, m, std::regex{"(.*):([\\d,]+)$"}))
    {
        std::string ports = m[2];
        for (size_t pos = 0; pos < ports.size();)
        {
            auto comma = ports.find(',', pos);
            tcp_ports.push_back(static_cast<uint16_t>(std::stoi(ports.substr(pos, comma - pos))));
            pos = comma == std::string::npos ? ports.size() : comma + 1;
        }
        port = tcp_ports.front();
        target = m[1];
    }
    if (tcp_ports.empty())
        tcp_ports.push_back(static_cast<uint16_t>(port));

    auto srouter = std::make_unique<session::router::SessionRouter>(std::filesystem::path{"jank.ini"});

    std::promise<void> prom;
    std::promise<void> conn_prom;

    // Holding these is what keeps the tunnels up; dropping them releases them (and, for TCP, closes
    // any connections established through it).
    session::router::udp_tunnel tunnel;
    std::vector<session::router::tcp_tunnel> tcps;

    // Opens the TCP tunnel before the session exists and connects to it straight away, to exercise
    // the documented promise that such a connection is held rather than refused.
    const bool early_probe = std::getenv("SR_TCP_EARLY") != nullptr;

    bool first_conn = true;
    srouter->on_connected([&] {
        if (!first_conn)
            return;
        first_conn = false;
        std::cout << "\n\x1b[32;1mSession Router connected!\x1b[0m\n\n";
        conn_prom.set_value();
    });
    auto open_tcp = [&srouter, &target, early_probe](uint16_t port) -> session::router::tcp_tunnel {
        auto t = srouter->establish_tcp(
            target,
            port,
            [port](auto info) {
                std::cout << "\n\x1b[32;1mTCP tunnel ready; remote port " << port << " reachable at [::1]:"
                          << info.local_port << "\x1b[0m\n\n"
                          << std::flush;
            },
            [](auto failure) {
                std::cerr << "\n\x1b[31;1mTCP tunnel failed: " << failure_reason(failure) << "\x1b[0m\n\n"
                          << std::flush;
            });

        if (t)
            std::cout << "\n\x1b[32;1mTCP bound to [::1]:" << t->local_port << " -> " << target << ":" << port
                      << "\x1b[0m\n\n";
        else
            std::cout << "\n\x1b[31;1mNo TCP tunnel: " << target
                      << " is unreachable or does not accept tunnelled TCP\x1b[0m\n\n";

        // With SR_TCP_EARLY set this fires while the session is still coming up, which is the case
        // the API documents (and which waiting for on_established would never reach).
        if (t && early_probe)
            std::thread{probe_tunnel, t->local_port, "/index.txt"}.detach();

        return t;
    };

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

        if (early_probe)
            for (auto p : tcp_ports)
                tcps.push_back(open_tcp(p));


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
                    throw std::runtime_error{"UDP tunnel failed: "s + std::string{failure_reason(failure)}};
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
        for (const auto& [snode, ip] : *current_path)
        {
            std::cout << "\tHop " << hop_count << ":\t" << snode << " @ " << ip << "\n";
            hop_count++;
        }
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

    if (tcps.empty())
        for (auto p : tcp_ports)
            tcps.push_back(open_tcp(p));


    std::thread sig_thread{[&] {
        while (srouter)
        {
            int signo;
            sigwait(&signal_mask, &signo);
            switch (signo)
            {
                case SIGHUP:
                    std::cout << "\n\n\n\x1b[33;1mHangup signal received; closing tunnels\x1b[0m\n\n\n";
                    tunnel.reset();
                    tcps.clear();
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
                    std::cout << "\n\n\n\x1b[32;1mSIGUSR2 received: (re-)opening TCP tunnel\x1b[0m\n";
                    tcps.clear();
                    for (auto p : tcp_ports)
                        tcps.push_back(open_tcp(p));
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
