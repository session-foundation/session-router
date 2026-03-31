#pragma once

// BT (bencode) encoding/decoding utilities for session-router wire format.
// Thin wrapper over oxen-encoding (oxenc) library.
//
// All session-router messages (except session data) are BT-encoded dicts.
// Dict keys are sorted lexicographically per the bencode specification.
//
// Signature convention: The "~" key always holds Ed25519 signature bytes.
// The signature covers the BT-encoded dict from the opening 'd' up to but
// NOT including the "~" key-value pair. This is the "append_signature" pattern.

#include <oxenc/bt.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/bt_value.h>

#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sr::encoding
{

    // Re-export oxenc types for convenience
    using oxenc::bt_dict_consumer;
    using oxenc::bt_dict_producer;
    using oxenc::bt_list_consumer;

    // Convert a BT-encoded string to a byte vector
    inline std::vector<std::byte> to_bytes(const std::string& bt_encoded)
    {
        return {
            reinterpret_cast<const std::byte*>(bt_encoded.data()),
            reinterpret_cast<const std::byte*>(bt_encoded.data() + bt_encoded.size())};
    }

    // Convert a byte span to a string_view for oxenc consumption
    inline std::string_view to_sv(std::span<const std::byte> data)
    {
        return {reinterpret_cast<const char*>(data.data()), data.size()};
    }

    // Convert a byte array to string_view
    template <size_t N>
    inline std::string_view to_sv(const std::array<std::byte, N>& arr)
    {
        return {reinterpret_cast<const char*>(arr.data()), N};
    }

    // Append raw bytes as a BT string value
    inline void append_bytes(bt_dict_producer& dp, std::string_view key, std::span<const std::byte> data)
    {
        dp.append(key, std::string_view{reinterpret_cast<const char*>(data.data()), data.size()});
    }

    // Append a fixed-size byte array as a BT string value
    template <size_t N>
    inline void append_bytes(bt_dict_producer& dp, std::string_view key, const std::array<std::byte, N>& arr)
    {
        dp.append(key, std::string_view{reinterpret_cast<const char*>(arr.data()), N});
    }

    // Append a uint32_t as a little-endian 4-byte BT string
    inline void append_le4(bt_dict_producer& dp, std::string_view key, uint32_t value)
    {
        std::array<char, 4> buf;
        std::memcpy(buf.data(), &value, 4);
        dp.append(key, std::string_view{buf.data(), 4});
    }

    // Read a 4-byte little-endian uint32 from a consumed BT string
    inline uint32_t read_le4(std::string_view sv)
    {
        uint32_t val = 0;
        if (sv.size() >= 4)
            std::memcpy(&val, sv.data(), 4);
        return val;
    }

    // Get the BT-encoded prefix for signing: everything from the opening 'd'
    // up to but not including the "~" key-value pair.
    // The input must be a complete BT dict string (starts with 'd', ends with 'e').
    std::string get_signable_prefix(const std::string& bt_dict);

    // Append an Ed25519 signature over the BT prefix to the dict.
    // This creates a new dict string with "~" appended at the end.
    std::string append_signature(
        const std::string& bt_prefix,
        const unsigned char* secret_key);

    // Verify the "~" signature in a BT dict.
    // Returns the inner dict (without "~") and validates the signature against pubkey.
    bool verify_signature(
        const std::string& bt_dict,
        const unsigned char* pubkey);

}  // namespace sr::encoding
