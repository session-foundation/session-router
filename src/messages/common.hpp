#pragma once

#include <string>
#include <string_view>

namespace srouter::messages
{
    using namespace std::literals;

    inline constexpr auto STATUS_KEY = "!"sv;
    std::string serialize_status_response(std::string_view value);

// MinGW: winnt.h STATUS_* macros collide with these string-view names
#ifdef STATUS_OK
#undef STATUS_OK
#endif
#ifdef STATUS_TIMEOUT
#undef STATUS_TIMEOUT
#endif
#ifdef STATUS_ERROR
#undef STATUS_ERROR
#endif
#ifdef STATUS_NOT_FOUND
#undef STATUS_NOT_FOUND
#endif
#ifdef STATUS_EXPIRED
#undef STATUS_EXPIRED
#endif
#ifdef STATUS_FUTURE
#undef STATUS_FUTURE
#endif
    constexpr auto STATUS_OK = "OK"sv;
    constexpr auto STATUS_TIMEOUT = "TIMEOUT"sv;
    constexpr auto STATUS_ERROR = "ERROR"sv;
    constexpr auto STATUS_NOT_FOUND = "NOT FOUND"sv;
    // Returned to indicate a timestamp (e.g. in a CC) that is too far in the past (indicating a client clock problem):
    constexpr auto STATUS_EXPIRED = "SLOW CLOCK"sv;
    // Returned to indicate a timestamp (e.g. in a CC) that is too far in the future (indicating a client clock
    // problem):
    constexpr auto STATUS_FUTURE = "FAST CLOCK"sv;

    extern const std::string OK_RESPONSE, TIMEOUT_RESPONSE, ERROR_RESPONSE, NOT_FOUND_RESPONSE, EXPIRED_RESPONSE,
        FUTURE_RESPONSE;
}  // namespace srouter::messages
