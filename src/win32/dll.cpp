#include "dll.hpp"

#include "util/logging.hpp"
#include "util/str.hpp"

namespace srouter::win32
{
    namespace
    {
        auto cat = log::Cat("win32-dll");
    }

    namespace detail
    {
        HMODULE
        load_dll(const std::string& dll)
        {
            auto handle = LoadLibraryExA(dll.c_str(), NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
            if (not handle)
                throw std::system_error(
                    static_cast<int>(GetLastError()), std::system_category(), fmt::format("failed to load '{}'", dll));
            log::info(cat, "loaded '{}'", dll);
            return handle;
        }
    }  // namespace detail
}  // namespace srouter::win32
