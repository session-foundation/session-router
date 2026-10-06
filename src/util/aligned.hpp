#pragma once

#include "cleared.hpp"

#include <oxenc/base32z.h>
#include <oxenc/bt.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <type_traits>

namespace srouter
{
    /// aligned buffer that is sz bytes long and aligns to the nearest Alignment.  If Clearing is
    /// true, then the underlying buffer includes a destructor that safely memzeros the value during
    /// destruction, and is recommended when this is used to store sensitive values.
    template <size_t sz, bool Clearing = false>
    struct alignas(8) AlignedBuffer
    {
        static_assert(sz % 8 == 0, "AlignedBuffer cannot be used with buffers that aren't a multiple of 8");

        static constexpr size_t SIZE = sz;

        AlignedBuffer() { zero(); }

        explicit AlignedBuffer(std::span<const uint8_t, SIZE> buf) { *this = buf; }
        explicit AlignedBuffer(std::span<const std::byte, SIZE> buf) { *this = buf; }

        AlignedBuffer& operator=(std::span<const uint8_t, SIZE> buf)
        {
            assign(buf);
            return *this;
        }
        AlignedBuffer& operator=(std::span<const std::byte, SIZE> buf)
        {
            assign(buf);
            return *this;
        }
        // Assigns to the aligned buffer contents from a spannable input of the same size
        void assign(std::span<const uint8_t, SIZE> buf) { std::memcpy(_data.data(), buf.data(), SIZE); }
        void assign(std::span<const std::byte, SIZE> buf) { std::memcpy(_data.data(), buf.data(), SIZE); }

        // Copies the aligned buffer contents into a writeable span of the same size
        void copy_to(std::span<std::byte, SIZE> buf) const { std::memcpy(buf.data(), _data.data(), SIZE); }
        void copy_to(std::span<uint8_t, SIZE> buf) const { std::memcpy(buf.data(), _data.data(), SIZE); }

        /// bitwise NOT
        AlignedBuffer<sz> operator~() const
        {
            AlignedBuffer<sz> ret;
            std::transform(begin(), end(), ret.begin(), [](uint8_t a) { return ~a; });

            return ret;
        }

        auto operator<=>(const AlignedBuffer& other) const = default;
        bool operator==(const AlignedBuffer& other) const = default;

        AlignedBuffer operator^(const AlignedBuffer& other) const
        {
            AlignedBuffer<sz> ret;
            std::transform(begin(), end(), other.begin(), ret.begin(), std::bit_xor<>());
            return ret;
        }

        AlignedBuffer& operator^=(const AlignedBuffer& other)
        {
            // Mutate in place instead.
            for (size_t i = 0; i < sz; ++i)
            {
                _data[i] ^= other._data[i];
            }
            return *this;
        }

        std::byte& operator[](size_t idx)
        {
            assert(idx < SIZE);
            return _data[idx];
        }

        const std::byte& operator[](size_t idx) const
        {
            assert(idx < SIZE);
            return _data[idx];
        }

        static constexpr size_t size() { return sz; }

        void Fill(std::byte f) { _data.fill(f); }

        std::array<std::byte, SIZE>& as_array() { return _data; }

        const std::array<std::byte, SIZE>& as_array() const { return _data; }

        std::byte* data() { return _data.data(); }
        const std::byte* data() const { return _data.data(); }

        unsigned char* udata() { return reinterpret_cast<unsigned char*>(data()); }
        const unsigned char* udata() const { return reinterpret_cast<const unsigned char*>(data()); }

        std::span<std::byte, SIZE> span()
        {
            return std::span<std::byte, SIZE>{reinterpret_cast<std::byte*>(_data.data()), SIZE};
        }
        std::span<const std::byte, SIZE> span() const
        {
            return std::span<const std::byte, SIZE>{reinterpret_cast<const std::byte*>(_data.data()), SIZE};
        }

        // Implicit conversion to fixed size span
        operator std::span<std::byte, SIZE>() { return span(); }
        operator std::span<const std::byte, SIZE>() const { return span(); }

        // Shortcut for .span().first/last:
        std::span<std::byte> first(size_t n) { return span().first(n); }
        std::span<const std::byte> first(size_t n) const { return span().first(n); }
        template <size_t N>
            requires(N <= SIZE)
        std::span<std::byte, N> first()
        {
            return span().template first<N>();
        }
        template <size_t N>
            requires(N <= SIZE)
        std::span<const std::byte, N> first() const
        {
            return span().template first<N>();
        }
        std::span<std::byte> last(size_t n) { return span().last(n); }
        std::span<const std::byte> last(size_t n) const { return span().last(n); }
        template <size_t N>
            requires(N <= SIZE)
        std::span<std::byte, N> last()
        {
            return span().template last<N>();
        }
        template <size_t N>
            requires(N <= SIZE)
        std::span<const std::byte, N> last() const
        {
            return span().template last<N>();
        }

        void zero() { Fill(std::byte{0}); }

        typename std::array<std::byte, SIZE>::iterator begin() { return _data.begin(); }

        typename std::array<std::byte, SIZE>::iterator end() { return _data.end(); }

        typename std::array<std::byte, SIZE>::const_iterator begin() const { return _data.cbegin(); }

        typename std::array<std::byte, SIZE>::const_iterator end() const { return _data.cend(); }

        bool from_base32z(std::string_view b32z)
        {
            if (b32z.size() != oxenc::to_base32z_size(sz) || !oxenc::is_base32z(b32z))
                return false;
            oxenc::from_base32z(b32z.begin(), b32z.end(), _data.begin());
            return true;
        }

        std::string bt_encode() const { return oxenc::bt_serialize(_data); }

        bool bt_decode(std::string buf)
        {
            oxenc::bt_deserialize(buf, _data);
            return true;
        }

        std::string_view to_view() const { return {reinterpret_cast<const char*>(data()), sz}; }

        std::string ToHex() const { return oxenc::to_hex(begin(), end()); }

        bool FromHex(std::string_view str)
        {
            if (str.size() != 2 * size() || !oxenc::is_hex(str))
                return false;
            oxenc::from_hex(str.begin(), str.end(), begin());
            return true;
        }

        std::string to_string() const { return ToHex(); }
        static constexpr bool to_string_formattable = true;

        // Deferred conversion object meant for log statements to be able to log a shortened b32z
        // value without needing to do the conversion when the log statement is skipped.
        struct short_log_printer
        {
            const AlignedBuffer<sz>& buf;
            std::string to_string() const { return oxenc::to_base32z(buf.begin(), buf.begin() + 5); }
            static constexpr bool to_string_formattable = true;
        };
        // Used in log statements to log the value as its first 8 base32z characters:
        short_log_printer short_string() const { return {*this}; }

        template <typename T>
            requires(std::derived_from<T, AlignedBuffer<T::SIZE>>)
        static T filled(std::byte f)
        {
            T ret;
            ret.Fill(f);
            return ret;
        }

      private:
        std::conditional_t<Clearing, cleared_barray<SIZE>, std::array<std::byte, SIZE>> _data;
    };

    static_assert(sizeof(AlignedBuffer<32>) == 32, "AlignedBuffer should have no overhead");
    static_assert(sizeof(AlignedBuffer<24>) == 24, "AlignedBuffer should have no overhead");
    static_assert(sizeof(AlignedBuffer<8>) == 8, "AlignedBuffer should have no overhead");

}  // namespace srouter

namespace std
{
    // Hashing implementation that uses the raw data value held in an AlignedBuffer-derived class as
    // the hash value.  This is only suitable for values that come from hashes or pubkeys where
    // values are unlikely to be correlated.
    template <size_t sz>
    struct hash<srouter::AlignedBuffer<sz>>
    {
        std::size_t operator()(const srouter::AlignedBuffer<sz>& buf) const noexcept
        {
            if constexpr (alignof(srouter::AlignedBuffer<sz>) >= sizeof(size_t))
                return *reinterpret_cast<const size_t*>(buf.data());
            else
            {
                std::size_t h;
                static_assert(srouter::AlignedBuffer<sz>::SIZE >= sizeof(h));
                std::memcpy(&h, buf.data(), sizeof(h));
                return h;
            }
        }
    };
}  // namespace std
