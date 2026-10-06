#include "config/config.hpp"  // for ensure_config
#include "constants/platform.hpp"
#include "constants/version.hpp"
#include "full/init.hpp"
#include "util/exceptions.hpp"
#include "util/thread/threading.hpp"

#include <CLI/CLI.hpp>
#include <fmt/core.h>
#include <oxen/log.hpp>
#include <oxen/quic/loop.hpp>
#include <session/router.hpp>
#include <session/router_context.hpp>

#include <csignal>
#include <memory>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#include "win32/service_manager.hpp"
#else
#include "util/service_manager.hpp"
#endif

namespace
{
    struct command_line_options
    {
        // bool options
        bool help = false;
        bool version = false;
        bool relay = false;

        std::filesystem::path config;

        std::string log_levels;

        // windows options
        bool win_install = false;
        bool win_remove = false;
    };

    // windows-specific function declarations
    int startWinsock();
    void install_win32_daemon();
    void uninstall_win32_daemon();

    // operational function definitions
    int srouter_main(int, char**);
    void handle_signal(int sig);
    void start_srouter(std::filesystem::path confFile, bool snode, std::string log_levels);

    // variable declarations
    static auto logcat = srouter::log::Cat("daemon");
    std::optional<srouter::Context> ctx;

    // operational function definitions
    void handle_signal(int sig)
    {
        srouter::log::info(logcat, "Handling signal {}", sig);

        if (ctx)
            ctx->signal(sig);
        else
            std::cerr << "Received signal " << sig << ", but have no context yet. Ignoring!" << std::endl;
    }

    // Windows specific code
#ifdef _WIN32
    extern "C" LONG FAR PASCAL win32_signal_handler(EXCEPTION_POINTERS*);
    extern "C" VOID FAR PASCAL win32_daemon_entry(DWORD, LPTSTR*);
    VOID insert_description();

    extern "C" BOOL FAR PASCAL handle_signal_win32(DWORD fdwCtrlType)
    {
        UNREFERENCED_PARAMETER(fdwCtrlType);
        handle_signal(SIGINT);
        return TRUE;  // probably unreachable
    };

    int startWinsock()
    {
        WSADATA wsockd;
        int err;
        err = ::WSAStartup(MAKEWORD(2, 2), &wsockd);
        if (err)
        {
            perror("Failed to start Windows Sockets");
            return err;
        }
        ::CreateMutex(nullptr, FALSE, "srouter_win32_daemon");
        return 0;
    }

    void install_win32_daemon()
    {
        SC_HANDLE schSCManager;
        SC_HANDLE schService;
        std::array<char, 1024> szPath{};

        if (!GetModuleFileName(nullptr, szPath.data(), MAX_PATH))
        {
            srouter::log::error(logcat, "Cannot install service {}", GetLastError());
            return;
        }

        // Get a handle to the SCM database.
        schSCManager = OpenSCManager(
            nullptr,                 // local computer
            nullptr,                 // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

        if (nullptr == schSCManager)
        {
            srouter::log::error(logcat, "OpenSCManager failed {}", GetLastError());
            return;
        }

        // Create the service
        schService = CreateService(
            schSCManager,                  // SCM database
            strdup("Session-Router"),      // name of service
            "Session Router for Windows",  // service name to display
            SERVICE_ALL_ACCESS,            // desired access
            SERVICE_WIN32_OWN_PROCESS,     // service type
            SERVICE_DEMAND_START,          // start type
            SERVICE_ERROR_NORMAL,          // error control type
            szPath.data(),                 // path to service's binary
            nullptr,                       // no load ordering group
            nullptr,                       // no tag identifier
            nullptr,                       // no dependencies
            nullptr,                       // LocalSystem account
            nullptr);                      // no password

        if (schService == nullptr)
        {
            srouter::log::error(logcat, "CreateService failed {}", GetLastError());
            CloseServiceHandle(schSCManager);
            return;
        }
        else
            srouter::log::info(logcat, "Service installed successfully");

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        insert_description();
    }

    VOID insert_description()
    {
        SC_HANDLE schSCManager;
        SC_HANDLE schService;
        SERVICE_DESCRIPTION sd;
        LPTSTR szDesc = strdup(
            "Session Router is a free, open source, private, "
            "decentralized, \"market based sybil resistant\" "
            "and IP based onion routing network");
        // Get a handle to the SCM database.
        schSCManager = OpenSCManager(
            NULL,                    // local computer
            NULL,                    // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

        if (nullptr == schSCManager)
        {
            srouter::log::error(logcat, "OpenSCManager failed {}", GetLastError());
            return;
        }

        // Get a handle to the service.
        schService = OpenService(
            schSCManager,            // SCM database
            "Session-Router",        // name of service
            SERVICE_CHANGE_CONFIG);  // need change config access

        if (schService == nullptr)
        {
            srouter::log::error(logcat, "OpenService failed {}", GetLastError());
            CloseServiceHandle(schSCManager);
            return;
        }

        // Change the service description.
        sd.lpDescription = szDesc;

        if (!ChangeServiceConfig2(
                schService,                  // handle to service
                SERVICE_CONFIG_DESCRIPTION,  // change: description
                &sd))                        // new description
        {
            srouter::log::error(logcat, "ChangeServiceConfig2 failed");
        }
        else
            srouter::log::info(log_cat, "Service description updated successfully.");

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }

    void uninstall_win32_daemon()
    {
        SC_HANDLE schSCManager;
        SC_HANDLE schService;

        // Get a handle to the SCM database.
        schSCManager = OpenSCManager(
            nullptr,                 // local computer
            nullptr,                 // ServicesActive database
            SC_MANAGER_ALL_ACCESS);  // full access rights

        if (nullptr == schSCManager)
        {
            srouter::log::error(logcat, "OpenSCManager failed {}", GetLastError());
            return;
        }

        // Get a handle to the service.
        schService = OpenService(
            schSCManager,      // SCM database
            "Session-Router",  // name of service
            0x10000);          // need delete access

        if (schService == nullptr)
        {
            srouter::log::error(logcat, "OpenService failed {}", GetLastError());
            CloseServiceHandle(schSCManager);
            return;
        }

        // Delete the service.
        if (!DeleteService(schService))
        {
            srouter::log::error(logcat, "DeleteService failed {}", GetLastError());
        }
        else
            srouter::log::info(logcat, "Service deleted successfully");

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }

    /// minidump generation for windows jizz
    /// will make a coredump when there is an unhandled exception
    LONG GenerateDump(EXCEPTION_POINTERS* pExceptionPointers)
    {
        const auto flags = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData
                                           | MiniDumpWithUnloadedModules | MiniDumpWithThreadInfo);

        const std::string fname =
            fmt::format("C:\\ProgramData\\Session-Router\\crash-{}.dump", srouter::time_now_ms().count());

        HANDLE hDumpFile;
        SYSTEMTIME stLocalTime;
        GetLocalTime(&stLocalTime);
        MINIDUMP_EXCEPTION_INFORMATION ExpParam{};

        hDumpFile = CreateFile(
            fname.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);

        ExpParam.ExceptionPointers = pExceptionPointers;
        ExpParam.ClientPointers = TRUE;

        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDumpFile, flags, &ExpParam, NULL, NULL);

        return 1;
    }

    VOID FAR PASCAL SvcCtrlHandler(DWORD dwCtrl)
    {
        // Handle the requested control code.

        switch (dwCtrl)
        {
            case SERVICE_CONTROL_STOP:
                // tell service we are stopping
                srouter::log::debug(logcat, "Windows service controller gave SERVICE_CONTROL_STOP");
                srouter::sys::service_manager->system_changed_our_state(srouter::sys::ServiceState::Stopping);
                handle_signal(SIGINT);
                return;

            case SERVICE_CONTROL_INTERROGATE:
                // report status
                srouter::log::debug(logcat, "Got win32 service interrogate signal");
                srouter::sys::service_manager->report_changed_state();
                return;

            default:
                srouter::log::debug(logcat, "Got win32 unhandled signal {}", dwCtrl);
                break;
        }
    }

    // The win32 daemon entry point is where we go when invoked as a windows service; we do the
    // required service dance and then pretend we were invoked via main().
    VOID FAR PASCAL win32_daemon_entry(DWORD, LPTSTR* argv)
    {
        // Register the handler function for the service
        auto* svc = dynamic_cast<srouter::sys::SVC_Manager*>(srouter::sys::service_manager);
        svc->handle = RegisterServiceCtrlHandler("Session-Router", SvcCtrlHandler);

        if (svc->handle == nullptr)
        {
            srouter::log::error(logcat, "failed to register daemon control handler");
            return;
        }

        // we hard code the args to srouter_main.
        // we yoink argv[0] (Session-Router.exe path) and pass in the new args.
        std::array args = {
            reinterpret_cast<char*>(argv[0]),
            reinterpret_cast<char*>(strdup("c:\\programdata\\Session-Router\\session-router.ini")),
            reinterpret_cast<char*>(0)};
        srouter_main(args.size() - 1, args.data());
    }

#endif

    int srouter_main(int argc, char** argv)
    {
#ifdef _WIN32
        if (startWinsock())
            return -1;
        SetConsoleCtrlHandler(handle_signal_win32, TRUE);
#endif

        CLI::App cli{
            "Session Router is a free, open source, private, decentralized, market-based sybil resistant "
            "and IP-based onion routing network"};
        command_line_options options{};

        // flags: boolean values in command_line_options struct
        cli.add_flag("--version", options.version, "Session Router version");
        cli.add_flag(
            "-r,--relay", options.relay, "Run Session Router as a relay (service node) instead of as a client");

        // options: string
        cli.add_option("config,-c,--config", options.config, "Path to session-router.ini configuration file")
            ->required();

        cli.add_option(
            "-l,--log-levels",
            options.log_levels,
            "Specify additional log levels to apply after the config file level");

        if constexpr (srouter::platform::is_windows)
        {
            cli.add_flag("--install", options.win_install, "Install win32 daemon to SCM");
            cli.add_flag("--remove", options.win_remove, "Remove win32 daemon from SCM");
        }

        try
        {
            cli.parse(argc, argv);
        }
        catch (const CLI::ParseError& e)
        {
            return cli.exit(e);
        }

        try
        {
            if (options.version)
            {
                std::cout << srouter::VERSION_FULL << std::endl;
                return 0;
            }

            if constexpr (srouter::platform::is_windows)
            {
                if (options.win_install)
                {
                    install_win32_daemon();
                    return 0;
                }
                if (options.win_remove)
                {
                    uninstall_win32_daemon();
                    return 0;
                }
            }
        }
        catch (const CLI::OptionNotFound& e)
        {
            cli.exit(e);
        }
        catch (const CLI::Error& e)
        {
            cli.exit(e);
        }

        auto type = options.relay ? srouter::config::Type::Relay : srouter::config::Type::FullClient;

        if (options.config.empty())
        {
            srouter::log::critical(logcat, "config file path cannot be empty");
            return 1;
        }
        if (!exists(options.config))
        {
            srouter::log::critical(logcat, "Config file '{}' not found", options.config);
            return 1;
        }

#ifdef _WIN32
        SetUnhandledExceptionFilter(&GenerateDump);
#endif

        try
        {
            start_srouter(std::move(options.config), options.relay, std::move(options.log_levels));
        }
        catch (const std::exception& e)
        {
            std::cerr << "\nSession Router failed to start: " << e.what() << "\n\n";
            return 1;
        }

        std::promise<void> watchdog_stop;
        std::thread watchdog{[ftr = watchdog_stop.get_future()] {
            srouter::util::SetThreadName("srtr-watchdog");
            while (ftr.wait_for(1s) != std::future_status::ready)
            {
                // do periodic non Session Router related tasks here
                if (ctx and ctx->is_running() and not ctx->looks_alive())
                {
                    auto deadlock_cat = srouter::log::Cat("deadlock");
                    srouter::log::critical(deadlock_cat, "Router has deadlocked!");
                    srouter::log::flush();
                    srouter::sys::service_manager->failed();
                    std::abort();
                }
            }
        }};

        ctx->wait();
        watchdog_stop.set_value();
        watchdog.join();

        srouter::log::flush();
        srouter::sys::service_manager->stopped();
        ctx.reset();
        return 0;
    }

    // this sets up, configures and runs the main context
    void start_srouter(std::filesystem::path confFile, bool snode, std::string log_level)
    {
        srouter::log::info(logcat, "starting {}", srouter::VERSION_FULL);
        try
        {
            auto type = snode ? srouter::config::Type::Relay : srouter::config::Type::FullClient;
            std::optional<srouter::Config> conf;
            try
            {
                conf.emplace(type, confFile);
            }
            catch (const std::exception& e)
            {
                srouter::log::error(logcat, "Failed to load config: {}", e.what());
                throw;
            }

            if (!log_level.empty())
            {
                if (!conf->logging.levels.empty())
                    conf->logging.levels += ';';
                conf->logging.levels += log_level;
            }

            ctx.emplace(/*embedded=*/false, std::move(*conf));

            signal(SIGINT, handle_signal);
            signal(SIGTERM, handle_signal);
            signal(SIGKILL, handle_signal);
        }
        catch (srouter::util::bind_socket_error& ex)
        {
            auto msg = "{}; is Session Router already running?"_format(ex.what());
            srouter::log::error(logcat, "{}", msg);
            throw std::runtime_error{msg};
        }
        catch (const std::exception& ex)
        {
            // Don't need to log here: context has already error logged the exception message
            throw;
        }
    }

}  // namespace

int main(int argc, char* argv[])
{
    // Set up a default, stderr logging for very early logging; we'll replace this later once we
    // read the desired log info from config.
    oxen::log::add_sink(srouter::log::Type::Print, "stderr");
    oxen::log::reset_level(srouter::log::Level::info);
    // oxen::log::set_level("quic", oxen::log::Level::info);

    // Set up full (non-embedded) application support (native service manager, stricter config
    // validators, ...).  Must happen before config is loaded and before the Context is constructed
    // (which calls give_context()) and, on win32, before the service control dispatcher runs.
    srouter::full::initialize();

    // TODO FIXME: this seems to be segfaulting?
    // srouter::logRingBuffer = std::make_shared<srouter::log::RingBufferSink>(100);
    // oxen::log::add_sink(srouter::logRingBuffer, srouter::log::DEFAULT_PATTERN_MONO);

#ifndef _WIN32
    return srouter_main(argc, argv);
#else
    if (auto hntdll = GetModuleHandle("ntdll.dll"))
    {
        if (GetProcAddress(hntdll, "wine_get_version"))
        {
            static const char* text = "Don't run Session Router in wine, aborting startup";
            static const char* title = "Session Router Wine Error";
            MessageBoxA(NULL, text, title, MB_ICONHAND);
            std::abort();
        }
    }

    SERVICE_TABLE_ENTRY DispatchTable[] = {
        {strdup("Session-Router"), (LPSERVICE_MAIN_FUNCTION)win32_daemon_entry}, {NULL, NULL}};

    // Try first to run as a service; if this works it fires off to win32_daemon_entry and doesn't
    // return until the service enters STOPPED state.
    if (StartServiceCtrlDispatcher(DispatchTable))
        return 0;

    auto error = GetLastError();

    // We'll get this error if not invoked as a service, which is fine: we can just run directly
    if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
    {
        srouter::sys::service_manager->disable();
        return srouter_main(argc, argv);
    }
    else
    {
        srouter::log::critical(logcat, "Error launching service: {}", std::system_category().message(error));
        return 1;
    }
#endif
}
