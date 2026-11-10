#pragma once

#include <string>
#include <string_view>

namespace srouter::messages
{
    using namespace std::literals;

    inline constexpr auto STATUS_KEY = "!"sv;
    std::string serialize_status_response(std::string_view value);

    constexpr auto STATUS_OK = "OK"sv;
    // Not STATUS_TIMEOUT: winnt.h defines that as a macro.
    constexpr auto STATUS_TIMED_OUT = "TIMEOUT"sv;
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
