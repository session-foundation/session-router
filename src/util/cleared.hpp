#include <array>
#include <span>
#include <type_traits>

namespace srouter
{

    // Sets the buffer to all 0 (NUL) bytes.  This uses libsodium's helper to ensure that the bytes
    // are actually set, i.e. cannot be skipped by an optimizing compiler.
    void set_zero(std::span<std::byte> buf);
    // Constant-time (for a given size) "is all 0s" check for a buffer
    bool is_zero(std::span<const std::byte> buf);

    template <typename T>
        requires std::is_trivially_destructible_v<T>
    struct sodium_cleared : T
    {
        using T::T;

        ~sodium_cleared() { set_zero({reinterpret_cast<std::byte*>(this), sizeof(*this)}); }
    };

    template <std::size_t N>
    using cleared_barray = sodium_cleared<std::array<std::byte, N>>;
    template <std::size_t N>
    using cleared_uarray = sodium_cleared<std::array<unsigned char, N>>;

    using cleared_uc32 = cleared_uarray<32>;
    using cleared_uc64 = cleared_uarray<64>;

}  // namespace srouter
