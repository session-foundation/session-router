#include "exec.hpp"

#include "util/logging.hpp"

#include <windows.h>

#include <array>
#include <system_error>

namespace srouter::win32
{
    namespace
    {
        static auto logcat = log::Cat("win32:exec");

        /// get the directory for system32 which contains all the executables we use
        std::string SystemExeDir()
        {
            std::array<char, MAX_PATH + 1> path{};

            if (GetSystemDirectoryA(path.data(), path.size()))
                return path.data();

            return "C:\\Windows\\system32";
        }

    }  // namespace

    void Exec(std::string exe, std::string args) { OneShotExec{exe, args}; }

    OneShotExec::OneShotExec(std::string cmd, std::chrono::milliseconds timeout)
        : _si{}, _pi{}, _timeout{static_cast<DWORD>(timeout.count())}
    {
        log::info(logcat, "exec: {}", cmd);
        if (not CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, false, 0, nullptr, nullptr, &_si, &_pi))
            throw std::system_error(
                static_cast<int>(GetLastError()), std::system_category(), "failed to execute subprocess");
    }

    OneShotExec::~OneShotExec()
    {
        WaitForSingleObject(_pi.hProcess, _timeout);
        CloseHandle(_pi.hProcess);
        CloseHandle(_pi.hThread);
    }

    OneShotExec::OneShotExec(std::string cmd, std::string args, std::chrono::milliseconds timeout)
        : OneShotExec{fmt::format("{}\\{} {}", SystemExeDir(), cmd, args), timeout}
    {}

    DeferExec::~DeferExec() { OneShotExec{std::move(_exe), std::move(_args), std::move(_timeout)}; }
}  // namespace srouter::win32
