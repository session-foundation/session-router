#pragma once

#include "ev/tcp.hpp"

#include <oxen/quic/address.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/crypto.hpp>
#include <oxen/quic/endpoint.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

namespace srouter::session
{
    namespace quic = oxen::quic;

    class Session;

    // Carries TCP connections over a session as streams of a QUIC connection nested inside the
    // session's data channel.  Session data is deliberately unreliable, so it is this inner
    // connection that supplies retransmission, ordering, flow control and congestion control; each
    // TCP connection becomes one stream, prefixed with the port it wants on the far end.
    //
    // The initiating side is a client mapping a remote port for a local application; the accepting
    // side is a client with a tun device, which terminates each stream into a TCP connection to its
    // own tun address.  A client without a tun device never accepts, and so never listens.
    struct TCPTunnel
    {
        explicit TCPTunnel(Session& session);
        ~TCPTunnel();

        TCPTunnel(const TCPTunnel&) = delete;
        TCPTunnel& operator=(const TCPTunnel&) = delete;

        // Feeds an inbound tunnelled packet from the session into the inner QUIC endpoint.
        void receive_packet(std::vector<std::byte>&& data);

        // Initiating side: pairs a newly accepted local TCP connection with a new stream requesting
        // `dest_port` on the far end.  Returns nullptr if no stream could be opened, in which case
        // the caller must drop the socket.
        TCPConnection* connect_stream(bufferevent* bev, TCPConnection::fd_t fd, uint16_t dest_port);

        // Drops the inner connection and every TCP connection riding on it; a later connect_stream()
        // builds a new one.  Listeners are owned elsewhere and deliberately outlive this.
        void reset();

        // Closes every connection this tunnel is carrying for the given remote port, used when the
        // last claim on that mapping goes away: releasing a mapping takes its connections with it.
        void close_connections_for(uint16_t dest_port);

      private:
        // Stream data that arrived before the local TCP connection for it existed, along with the
        // destination port preamble that precedes it.
        struct pending_stream
        {
            std::vector<std::byte> buffered;
            bool connecting{false};
        };

        struct live_conn
        {
            std::shared_ptr<TCPConnection> conn;

            // The remote port this connection was mapped to, for connections we initiated; 0 for
            // streams we accepted, which belong to no local mapping and so are never closed by one
            // being released.
            uint16_t mapped_port{0};
        };

        Session& _session;

        std::shared_ptr<quic::TLSCreds> _tls_creds;
        std::shared_ptr<quic::Endpoint> _ep;
        std::shared_ptr<quic::Connection> _conn;

        // Live TCP connections.  Keyed by an id of our own rather than the stream id: a stream
        // opened past the peer's stream limit is pending and has no id assigned yet, and those
        // placeholder ids are not distinct, so keying on them loses connections.
        std::unordered_map<uint64_t, live_conn> _conns;
        uint64_t _next_conn_id{0};

        bool _idle_teardown_scheduled{false};

        // Lets deferred callbacks tell that we are gone: some of them fire from libquic destructors,
        // by which point our members are no longer valid objects.
        std::shared_ptr<bool> _alive{std::make_shared<bool>(true)};

        void open_connection();

        uint64_t on_stream_opened(quic::Stream& stream);
        void start_accepted_stream(std::shared_ptr<quic::Stream> stream, std::shared_ptr<pending_stream> pending);

        void adopt(std::shared_ptr<TCPConnection> conn, uint16_t mapped_port);
        void drop(uint64_t conn_id);
        void schedule_idle_teardown();

        // Where the accepting side sends a tunnelled connection asking for `port`: our own tun
        // address, or nullopt if we have no tun device and so cannot accept at all.
        std::optional<quic::Address> accept_target(uint16_t port) const;
    };

}  // namespace srouter::session
