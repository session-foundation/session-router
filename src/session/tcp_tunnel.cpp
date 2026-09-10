#include "tcp_tunnel.hpp"

#include "handlers/tun_interface.hpp"
#include "net/traffic_type.hpp"
#include "router/router.hpp"
#include "session.hpp"
#include "util/logging.hpp"

#include <event2/bufferevent.h>
#include <oxen/quic/opt.hpp>
#include <oxen/quic/unencrypted.hpp>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

namespace srouter::session
{
    static auto logcat = log::Cat("tcp");

    // The inner connection never touches a real socket, so its addresses are arbitrary; they exist
    // only because ngtcp2 requires a path.
    static const quic::Address FAKE_QUIC_ADDR{"127.86.75.30"s, 9};
    static const quic::Path FAKE_QUIC_PATH{FAKE_QUIC_ADDR, FAKE_QUIC_ADDR};

    // Each TCP connection takes a stream, so the default (32) is far too few for something like a
    // browser.
    inline constexpr uint64_t INNER_MAX_STREAMS = 256;

    // QUIC closes a connection with no activity *at all* on it, which would kill a TCP connection
    // that is merely idle (an ssh session, a long poll), so we ping to hold it open.  We only pay
    // for that while connections exist: an inner connection with no streams left is torn down after
    // INNER_IDLE_TEARDOWN, making a dormant tunnel free.
    inline constexpr auto INNER_IDLE_TIMEOUT = 5min;
    inline constexpr auto INNER_KEEP_ALIVE = 30s;
    inline constexpr auto INNER_IDLE_TEARDOWN = 60s;

    // The destination port sent as the first bytes of each stream.
    inline constexpr size_t PORT_PREAMBLE_SIZE = 2;

    TCPTunnel::TCPTunnel(Session& session) : _session{session}
    {
        // The inner connection carries nothing that the session layer has not already encrypted end
        // to end and the path layer onion-encrypted, and its peer is authenticated by the session
        // itself, so QUIC's own crypto here would only buy a second AEAD pass and a handshake.
        _tls_creds = quic::DangerouslyUnencryptedCreds::i_know_this_traffic_is_already_encrypted();

        quic::opt::manual_routing send_hook{[this](const quic::Path&, std::span<const std::byte> data) {
            _session.send_session_data_message(data, traffic_type::TUNNELED_QUIC);
        }};

        quic::connection_established_callback on_established{[this](quic::Connection& conn) {
            // Outbound connections are already recorded by open_connection(), so seeing ourselves
            // here is normal; a *different* connection means the far end opened a second one.
            if (_conn)
            {
                if (_conn.get() != &conn)
                    log::error(logcat, "Already have a QUIC tunnel connection for session to {}!", _session._remote);
                return;
            }
            log::debug(logcat, "QUIC tunnel connection for session to {} established", _session._remote);
            _conn = conn.shared_from_this();
        }};

        quic::connection_closed_callback on_closed{
            [this, alive = std::weak_ptr{_alive}](quic::Connection&, uint64_t ec) {
                // This can fire from the Endpoint destructor, at which point our members are gone.
                if (!alive.lock())
                    return;
                log::debug(logcat, "QUIC tunnel connection for session to {} closed ({})", _session._remote, ec);
                reset();
            }};

        _ep = quic::Endpoint::endpoint(
            _session._r.loop(),
            FAKE_QUIC_ADDR,
            std::move(send_hook),
            std::move(on_established),
            std::move(on_closed),
            // TODO: drop to the single-datagram budget (1076) once libquic allows a sub-1200 cap on
            // manually routed endpoints; at 1200 an inner packet needs an outer payload of 1324 to
            // avoid being split across two path datagrams.
            quic::opt::max_udp_payload::minimum());

        // Only a client with a tun device can terminate an inbound stream into a local TCP
        // connection, so only such a client accepts them.
        // These have to match what open_connection() sets: the stream limit each side advertises is
        // what caps the *other* side, and the idle timeout in force is the lower of the two, so
        // leaving the accepting side at the defaults would cap streams at 32 and expire the
        // connection after 30s -- killing connections that are merely idle.
        if (_session._r.tun_endpoint())
            _ep->listen(
                _tls_creds,
                quic::opt::max_streams{INNER_MAX_STREAMS},
                quic::opt::idle_timeout{INNER_IDLE_TIMEOUT},
                [this](quic::Stream& s) { return on_stream_opened(s); });
    }

    TCPTunnel::~TCPTunnel()
    {
        log::trace(logcat, "Tearing down TCP tunnel for session to {}", _session._remote);
        _conns.clear();
    }

    void TCPTunnel::receive_packet(std::vector<std::byte>&& data)
    {
        _ep->manually_receive_packet(quic::Packet{FAKE_QUIC_PATH, std::move(data)});
    }

    void TCPTunnel::open_connection()
    {
        if (_conn)
            return;

        log::debug(logcat, "Opening QUIC tunnel connection for session to {}", _session._remote);

        _conn = _ep->connect(
            // No remote key to verify: nothing here authenticates anything, and the session this
            // rides inside has already authenticated the peer.
            quic::RemoteAddress{""sv, FAKE_QUIC_ADDR},
            _tls_creds,
            quic::opt::max_streams{INNER_MAX_STREAMS},
            quic::opt::idle_timeout{INNER_IDLE_TIMEOUT},
            quic::opt::keep_alive{INNER_KEEP_ALIVE});
    }

    TCPConnection* TCPTunnel::connect_stream(bufferevent* bev, TCPConnection::fd_t fd, uint16_t dest_port)
    {
        open_connection();
        if (!_conn)
        {
            log::warning(logcat, "No QUIC tunnel connection to {}; cannot tunnel TCP connection", _session._remote);
            return nullptr;
        }

        auto stream = _conn->open_stream<quic::Stream>();
        if (!stream)
        {
            log::warning(logcat, "Failed to open a tunnel stream to {}", _session._remote);
            return nullptr;
        }

        std::string preamble;
        preamble.resize(PORT_PREAMBLE_SIZE);
        oxenc::write_host_as_big(dest_port, preamble.data());
        stream->send(std::move(preamble));

        auto conn = std::make_shared<TCPConnection>(bev, fd, stream);
        auto* ptr = conn.get();
        adopt(std::move(conn), dest_port);

        log::debug(
            logcat,
            "Tunnelling TCP connection to {}:{} over stream {}",
            _session._remote,
            dest_port,
            stream->stream_id());

        return ptr;
    }

    uint64_t TCPTunnel::on_stream_opened(quic::Stream& stream)
    {
        // Hold the stream until we know where it is going and have a socket for it.  The pause only
        // stops the window from being extended, so the port preamble still arrives.
        stream.pause();

        auto pending = std::make_shared<pending_stream>();

        stream.set_data_callback(
            [this, pending, alive = std::weak_ptr{_alive}](quic::Stream& s, std::span<const std::byte> data) {
                if (!alive.lock())
                    return;

                pending->buffered.insert(pending->buffered.end(), data.begin(), data.end());

                if (pending->connecting || pending->buffered.size() < PORT_PREAMBLE_SIZE)
                    return;
                pending->connecting = true;

                // Handing the stream to a TCPConnection replaces this very callback, which cannot be
                // done from inside it, so the connect happens on the next loop iteration.  Anything
                // that arrives in the meantime keeps accumulating in `pending`.
                _session._r.loop().call_soon(
                    [this, pending, stream = s.shared_from_this(), alive = std::move(alive)]() mutable {
                        if (!alive.lock())
                            return;
                        start_accepted_stream(std::move(stream), std::move(pending));
                    });
            });

        return 0;
    }

    void TCPTunnel::start_accepted_stream(std::shared_ptr<quic::Stream> stream, std::shared_ptr<pending_stream> pending)
    {
        auto dest_port = oxenc::load_big_to_host<uint16_t>(pending->buffered.data());
        if (dest_port == 0)
        {
            log::warning(logcat, "Refusing tunnelled stream {}: port 0 is not a destination", stream->stream_id());
            stream->close(tunnel_error::REFUSED);
            return;
        }

        auto target = accept_target(dest_port);
        if (!target)
        {
            log::warning(logcat, "Refusing tunnelled connection to port {}: no tun device to serve it", dest_port);
            stream->close(tunnel_error::REFUSED);
            return;
        }

        log::debug(logcat, "Tunnelled stream {} from {} wants {}", stream->stream_id(), _session._remote, *target);

        auto stream_id = stream->stream_id();
        auto conn = TCPHandle::connect(_session._r.loop(), *target, std::move(stream));
        if (!conn)
        {
            log::warning(logcat, "Could not connect to {} for tunnelled stream {}", *target, stream_id);
            return;
        }

        // Whatever arrived while we were setting up has to go out ahead of anything the socket
        // subsequently carries.
        if (auto rest = std::span{pending->buffered}.subspan(PORT_PREAMBLE_SIZE); !rest.empty())
            bufferevent_write(conn->bev, rest.data(), rest.size());

        // An accepted stream belongs to no local mapping, so it carries no mapped port.
        adopt(std::move(conn), 0);
    }

    void TCPTunnel::adopt(std::shared_ptr<TCPConnection> conn, uint16_t mapped_port)
    {
        auto conn_id = _next_conn_id++;

        conn->on_done = [this, conn_id, alive = std::weak_ptr{_alive}]() {
            if (!alive.lock())
                return;
            drop(conn_id);
        };

        _conns[conn_id] = live_conn{.conn = std::move(conn), .mapped_port = mapped_port};
    }

    void TCPTunnel::close_connections_for(uint16_t dest_port)
    {
        for (auto& [stream_id, live] : _conns)
        {
            if (live.mapped_port != dest_port)
                continue;

            log::debug(logcat, "Closing tunnelled connection on stream {}: its mapping was released", stream_id);
            live.conn->close();
        }
    }

    void TCPTunnel::drop(uint64_t conn_id)
    {
        // This runs from inside a bufferevent or stream callback belonging to the connection we are
        // dropping, so its destruction has to wait until we are out of it.
        _session._r.loop().call_soon([this, conn_id, alive = std::weak_ptr{_alive}]() {
            if (!alive.lock())
                return;

            _conns.erase(conn_id);
            log::debug(logcat, "Tunnelled connection {} finished; {} left", conn_id, _conns.size());

            if (_conns.empty())
                schedule_idle_teardown();
        });
    }

    void TCPTunnel::schedule_idle_teardown()
    {
        if (_idle_teardown_scheduled)
            return;
        _idle_teardown_scheduled = true;

        _session._r.loop().call_later(INNER_IDLE_TEARDOWN, [this, alive = std::weak_ptr{_alive}]() {
            if (!alive.lock())
                return;
            _idle_teardown_scheduled = false;

            // Something started using it again while we were waiting; a later drop re-schedules.
            if (!_conns.empty())
                return;

            if (_conn)
            {
                log::debug(logcat, "Closing idle QUIC tunnel connection to {}", _session._remote);
                _conn->close_connection();
                _conn.reset();
            }
        });
    }

    void TCPTunnel::reset()
    {
        log::trace(logcat, "Resetting TCP tunnel for session to {}", _session._remote);
        _conn.reset();
        _conns.clear();
    }

    std::optional<quic::Address> TCPTunnel::accept_target(uint16_t port) const
    {
        const auto& tun = _session._r.tun_endpoint();
        if (!tun)
            return std::nullopt;

        // IPv6 only: it is always active on a tun client, and IPv4 is on its way out.
        auto v6 = tun->get_ipv6_network().ip;
        if (v6 == quic::ipv6{})
        {
            log::warning(logcat, "Cannot accept tunnelled TCP: tun device has no IPv6 address");
            return std::nullopt;
        }

        return quic::Address{v6, port};
    }

}  // namespace srouter::session
