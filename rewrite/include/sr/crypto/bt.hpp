#pragma once

// Re-export oxen-encoding BT serialization.
// This is the wire format for all session-router messages.

#include <oxenc/bt.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_value.h>

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sr::bt {

using namespace oxenc;

// Convenience: serialize a bt_dict_producer to bytes
inline std::vector<std::byte> to_bytes(const std::string& bt_encoded) {
    return {reinterpret_cast<const std::byte*>(bt_encoded.data()),
            reinterpret_cast<const std::byte*>(bt_encoded.data() + bt_encoded.size())};
}

inline std::string_view to_sv(std::span<const std::byte> data) {
    return {reinterpret_cast<const char*>(data.data()), data.size()};
}

}  // namespace sr::bt
