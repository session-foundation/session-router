#include "cleared.hpp"

#include <sodium/utils.h>

namespace srouter
{

    void set_zero(std::span<std::byte> buf) { sodium_memzero(buf.data(), buf.size()); }

    bool is_zero(std::span<const std::byte> buf)
    {
        return sodium_is_zero(reinterpret_cast<const unsigned char*>(buf.data()), buf.size());
    }

}  // namespace srouter
