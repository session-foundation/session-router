#include <sr/contact/router_id.hpp>

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace sr::contact
{

    RouterID::RouterID(std::span<const std::byte, 32> data) { std::memcpy(_pk.data(), data.data(), 32); }

    std::string RouterID::to_string() const
    {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto b : _pk)
            ss << std::setw(2) << static_cast<int>(static_cast<uint8_t>(b));
        return ss.str();
    }

    RouterID RouterID::from_string(std::string_view hex)
    {
        if (hex.size() != 64)
            throw std::invalid_argument("RouterID hex string must be 64 characters");

        sr::crypto::Ed25519PubKey pk;
        for (size_t i = 0; i < 32; ++i)
        {
            auto byte_str = hex.substr(i * 2, 2);
            auto val = std::stoul(std::string(byte_str), nullptr, 16);
            pk[i] = static_cast<std::byte>(val);
        }
        return RouterID{pk};
    }

}  // namespace sr::contact
