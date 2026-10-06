#pragma once
#include <type_traits>

namespace srouter
{
    // Turn an enum into its underlying value.
#ifdef __cpp_lib_to_underlying
    using std::to_underlying;
#else
    template <class Enum>
        requires std::is_enum_v<Enum>
    constexpr std::underlying_type_t<Enum> to_underlying(Enum e) noexcept
    {
        return static_cast<std::underlying_type_t<Enum>>(e);
    }
#endif

}  // namespace srouter
