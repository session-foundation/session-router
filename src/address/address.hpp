#pragma once

#include "contact/router_id.hpp"
#include "contact/sns.hpp"
#include "util/aligned.hpp"

namespace srouter
{
    // The TLDs we use to refer to a relay or client by base32z pubkey:
    inline constexpr auto RELAY_DOT_TLD = ".snode"sv;
    inline constexpr auto RELAY_TLD = RELAY_DOT_TLD.substr(1);
    inline constexpr auto CLIENT_DOT_TLD = ".sesh"sv;
    inline constexpr auto CLIENT_TLD = CLIENT_DOT_TLD.substr(1);

    /// Combines a pubkey and client/snode flag to represent a generic (client or snode) address.
    struct NetworkAddress
    {
        RouterID pubkey{};
        bool is_client{false};

        NetworkAddress() = default;

        // Constructs from a full network address ending in '.sesh' or '.snode' (but *not* an ONS
        // entry).  Throws std::invalid_argument if invalid.
        explicit NetworkAddress(std::string_view addr);

        // Constructs from a full network address (base32z-encoded pubkey) *not* ending in .sesh or
        // .snode.  The client or snode status is determined by the bool.
        NetworkAddress(std::string_view addr, bool is_client);

        // Constructs from a pubkey and flag indicating whether this is a client (true) or snode
        // (false).
        NetworkAddress(const RouterID& rid, bool is_client) : pubkey{rid}, is_client{is_client} {}

        bool operator==(const NetworkAddress& other) const = default;

        bool empty() const { return is_zero(pubkey); }

        bool client() const { return is_client; }

        bool relay() const { return !is_client; }

        // Returns a log proxy object that prints a shortened part of the pubkey:
        auto short_name() const { return pubkey.short_string(); }

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

}  // namespace srouter

template <>
struct std::hash<srouter::NetworkAddress>
{
    size_t operator()(const srouter::NetworkAddress& r) const { return std::hash<srouter::RouterID>{}(r.pubkey); }
};
