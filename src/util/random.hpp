#pragma once

#include <sodium/randombytes.h>

#include <limits>
#include <span>

namespace srouter
{
    /// RNG type that produces cryptographically secure random values.
    struct CSRNG
    {
        using result_type = uint64_t;

        static constexpr uint64_t min() { return std::numeric_limits<uint64_t>::min(); }

        static constexpr uint64_t max() { return std::numeric_limits<uint64_t>::max(); }

        uint64_t operator()()
        {
            uint64_t i;
            randombytes_buf(&i, sizeof(i));
            return i;
        }
    };

    extern CSRNG csrng;

    inline void random_fill(std::span<std::byte> s) { randombytes_buf(s.data(), s.size()); }
    inline void random_fill(std::span<unsigned char> s) { randombytes_buf(s.data(), s.size()); }

}  // namespace srouter
