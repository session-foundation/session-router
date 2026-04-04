#pragma once

#include <sr/link/connection_info.hpp>

#include <cstdint>
#include <functional>
#include <memory>

namespace sr::link
{

    // Close callback type for relay_conn to notify on close
    using CloseCallback = std::function<void(uint64_t errcode)>;

    // Stores relay-to-relay connections. Allows simultaneous connections in both
    // directions between a pair of relays, then after a timeout both sides choose
    // the same winner and drop the other.
    //
    // Winner selection: inbound_wins = (their_rid < our_rid)
    // Both sides compute the same answer — symmetric.
    struct relay_conn
    {
        // Constructor: inbound_wins is true if the inbound connection should take
        // precedence when both directions exist. Determined by comparing RouterIDs
        // so both sides agree.
        explicit relay_conn(bool inbound_wins) : inbound_wins{inbound_wins} {}

        bool inbound_wins;
        std::shared_ptr<ConnectionInfo> inbound;
        std::shared_ptr<ConnectionInfo> outbound;

        // Pointer to the current preferred connection, or nullptr if none.
        ConnectionInfo* conn = nullptr;

        // Sets the appropriate inbound/outbound pointer. If this is the only or
        // the winning connection, also sets it to `conn`. If the existing pointer
        // is already set, the old connection is closed before replacement.
        void set_conn(std::shared_ptr<ConnectionInfo> c, bool is_inbound);

        // Closes either inbound or outbound direction. If the other still exists,
        // `conn` is updated to point at it. Otherwise set to nullptr.
        void close(bool direction_inbound, uint64_t errcode = 0);

        // Closes all connections in both directions.
        void close_all(uint64_t errcode = 0);

        // Closes the "loser" connection when both directions exist.
        void close_redundant();

        // Error code used when closing redundant connections.
        static constexpr uint64_t CONN_CLOSE_REDUNDANT = 6;
    };

}  // namespace sr::link
