#pragma once

#include <windows.h>

#include <system_error>

namespace srouter::win32
{
    inline void ensure_handle_is_valid(HANDLE h)
    {
        BY_HANDLE_FILE_INFORMATION info{};
        if (GetFileInformationByHandle(h, &info))
            return;
        if (auto err = GetLastError())
        {
            SetLastError(0);
            throw std::system_error(static_cast<int>(err), std::system_category(), "handle validity check failed");
        }
    }
}  // namespace srouter::win32
