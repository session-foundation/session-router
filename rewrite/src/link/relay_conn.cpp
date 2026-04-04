#include <sr/link/relay_conn.hpp>

namespace sr::link
{

    void relay_conn::set_conn(std::shared_ptr<ConnectionInfo> c, bool is_inbound)
    {
        auto& ptr = is_inbound ? inbound : outbound;
        // If direction already has a connection, the old one is replaced (caller
        // is responsible for closing it if desired).
        ptr = std::move(c);

        // Update preferred connection: use this direction if it's the only one,
        // or if it's the winning direction.
        if (is_inbound ? !outbound || inbound_wins : !inbound || !inbound_wins)
            conn = ptr.get();
    }

    void relay_conn::close(bool direction_inbound, uint64_t /*errcode*/)
    {
        auto& to_close = direction_inbound ? inbound : outbound;
        if (!to_close)
            return;

        to_close.reset();

        // Switch preferred to the other direction (nullptr if it doesn't exist)
        conn = (direction_inbound ? outbound : inbound).get();
    }

    void relay_conn::close_all(uint64_t /*errcode*/)
    {
        inbound.reset();
        outbound.reset();
        conn = nullptr;
    }

    void relay_conn::close_redundant()
    {
        // Close the loser direction
        close(!inbound_wins, CONN_CLOSE_REDUNDANT);
    }

}  // namespace sr::link
