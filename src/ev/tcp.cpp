#include "tcp.hpp"

#include "util/formattable.hpp"
#include "util/logging.hpp"
#include "util/logging/buffer.hpp"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

namespace srouter
{
    static_assert(std::same_as<evutil_socket_t, TCPConnection::fd_t>);

    static auto logcat = oxen::log::Cat("tcp");

    // Backpressure thresholds.  The stream pair stops us reading from the application when the
    // tunnel is not keeping up; the socket pair pauses the stream when the application is not
    // keeping up.  Both need enough hysteresis to avoid flapping on a high-latency path, where a
    // full bandwidth-delay product of data can legitimately be in flight.
    inline constexpr size_t STREAM_ALARM_WATER = size_t{512} * 1024;
    inline constexpr size_t STREAM_CLEAR_WATER = size_t{64} * 1024;
    inline constexpr size_t SOCKET_ALARM_WATER = size_t{512} * 1024;
    inline constexpr size_t SOCKET_CLEAR_WATER = size_t{64} * 1024;

    constexpr auto evconnlistener_deleter = [](::evconnlistener *e) {
        log::trace(logcat, "Invoking evconnlistener deleter!");
        if (e)
            evconnlistener_free(e);
    };

    /// Checks rv for being -1 and, if so, raises a system_error from errno.  Otherwise returns it.
    static int check_rv(int rv)
    {
#ifdef _WIN32
        if (rv == SOCKET_ERROR)
            throw std::system_error{WSAGetLastError(), std::system_category()};
#else
        if (rv == -1)
            throw std::system_error{errno, std::system_category()};
#endif
        return rv;
    }

    static void tcp_read_cb(bufferevent *bev, void *user_arg)
    {
        auto *conn = reinterpret_cast<TCPConnection *>(user_arg);
        assert(conn);

        std::vector<uint8_t> buf{};
        buf.resize(evbuffer_get_length(bufferevent_get_input(bev)));
        if (buf.empty())
            return;

        buf.resize(bufferevent_read(bev, buf.data(), buf.size()));

        log::trace(logcat, "TCP socket received {}B: {}", buf.size(), buffer_printer{buf});

        conn->stream->send(std::move(buf));
    };

    static void tcp_write_cb([[maybe_unused]] bufferevent *bev, void *user_arg)
    {
        auto *conn = reinterpret_cast<TCPConnection *>(user_arg);
        conn->on_write_available();
    }

    void TCPConnection::on_write_available()
    {
        log::debug(logcat, "TCP Tunnel connection, write to local conn was blocked but is now available.");
        if (stream->is_paused())
            stream->resume();

        // A half-close we could not act on earlier because data was still queued for the app.
        if (_fin_received)
            flush_and_shutdown_write();
    }

    static void tcp_event_cb(bufferevent *bev, short what, void *user_arg)
    {
        (void)bev;
        (void)user_arg;
        auto *conn = reinterpret_cast<TCPConnection *>(user_arg);
        assert(conn);

        log::log(
            logcat,
            what & BEV_EVENT_ERROR ? log::Level::err : log::Level::debug,
            "TCP Connection {} event: {}",
            what & BEV_EVENT_READING ? "READ" : "WRITE",
            what & BEV_EVENT_EOF             ? "EOF"
                : what & BEV_EVENT_ERROR     ? "ERROR"
                : what & BEV_EVENT_TIMEOUT   ? "TIMEOUT"
                : what & BEV_EVENT_CONNECTED ? "CONNECTED"
                                             : "IMPOSSIBLE");

        // This is where the accepting side confirms it established a TCP connection to the backend
        // app; the stream is held paused until then so that no data is lost before the socket exists.
        if (what & BEV_EVENT_CONNECTED)
        {
            log::debug(logcat, "TCP connect operation finished!");
            conn->_connected = true;
            conn->stream->resume();
            return;
        }

        // An error before the socket ever came up means we could not reach the target at all, which
        // the far end needs to be able to tell apart from a connection that broke mid-stream.
        if (what & BEV_EVENT_ERROR)
        {
            log::warning(
                logcat,
                "TCP Connection encountered error from bufferevent: {}",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            conn->close(conn->_connected ? tunnel_error::TCP_FAILURE : tunnel_error::CONNECT_FAILED);
            return;
        }

        if (what & BEV_EVENT_EOF)
            conn->on_tcp_eof();
    };

    static void tcp_listen_cb(
        struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *src, int socklen, void *user_arg)
    {
        quic::Address source{src, static_cast<socklen_t>(socklen)};
        log::debug(logcat, "TCP RECEIVED -- SRC:{}", source);

        auto *b = evconnlistener_get_base(listener);
        auto *bevent = bufferevent_socket_new(b, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

        auto *handle = reinterpret_cast<TCPHandle *>(user_arg);
        assert(handle);

        // make TCPConnection here!
        auto *conn = handle->_conn_maker(bevent, fd);
        if (!conn)
        {
            log::warning(logcat, "Could not tunnel incoming TCP connection from {}; dropping it", source);
            bufferevent_free(bevent);
            return;
        }

        bufferevent_setcb(bevent, tcp_read_cb, tcp_write_cb, tcp_event_cb, conn);
        bufferevent_enable(bevent, EV_READ | EV_WRITE);
    };

    static void tcp_err_cb(struct evconnlistener * /* e */, void *user_arg)
    {
        int ec = EVUTIL_SOCKET_ERROR();
        log::critical(logcat, "TCP LISTENER RECEIVED ERROR CODE {}:{}", ec, evutil_socket_error_to_string(ec));

        auto *handle = reinterpret_cast<TCPHandle *>(user_arg);
        assert(handle);
        (void)handle;

        // DISCUSS: close everything here?
    };

    TCPConnection::TCPConnection(bufferevent *_bev, evutil_socket_t _fd, std::shared_ptr<quic::Stream> s)
        : bev{_bev}, fd{_fd}, stream{std::move(s)}
    {
        stream->set_data_callback([this](quic::Stream &s, std::span<const std::byte> data) {
            if (bufferevent_write(bev, data.data(), data.size()) != 0)
            {
                log::warning(
                    logcat, "Failed to write {}B from stream (id:{}) to TCP socket", data.size(), s.stream_id());
                close(tunnel_error::TCP_FAILURE);
                return;
            }

            log::trace(logcat, "Stream (id:{}) wrote {}B to TCP buffer", s.stream_id(), data.size());

            // A bufferevent's output buffer grows without limit, so the only backpressure available
            // here is to stop the far end once the application is visibly failing to keep up.
            if (!s.is_paused() && evbuffer_get_length(bufferevent_get_output(bev)) >= SOCKET_ALARM_WATER)
            {
                log::debug(logcat, "App is behind on stream (id:{}); pausing the tunnelled stream", s.stream_id());
                s.pause();
            }
        });

        stream->set_fin_callback([this](quic::Stream &) { on_stream_fin(); });

        stream->set_close_callback([this](quic::Stream &s, uint64_t ec) {
            if (ec != 0)
                log::debug(logcat, "Tunnelled stream (id:{}) closed by remote with error code {}", s.stream_id(), ec);
            finish();
        });

        stream->enable_watermarks(
            STREAM_ALARM_WATER,
            [this](quic::Stream &) { stop_reading(); },
            STREAM_CLEAR_WATER,
            [this](quic::Stream &) { resume_reading(); });

        // Fire the write callback once the app has drained down to here, which is what lets us
        // un-pause the stream and act on a deferred half-close.
        bufferevent_setwatermark(bev, EV_WRITE, SOCKET_CLEAR_WATER, 0);
    }

    void TCPConnection::on_tcp_eof()
    {
        if (_fin_sent)
            return;
        _fin_sent = true;

        log::debug(logcat, "Local TCP side closed; passing the half-close on to the tunnelled stream");
        bufferevent_disable(bev, EV_READ);
        stream->send_fin();

        if (_write_shutdown)
            finish();
    }

    void TCPConnection::on_stream_fin()
    {
        log::debug(logcat, "Tunnelled stream finished sending; shutting down our TCP write side");
        _fin_received = true;
        flush_and_shutdown_write();
    }

    void TCPConnection::flush_and_shutdown_write()
    {
        if (_write_shutdown)
            return;

        // Shutting down while data is still queued for the app would truncate it; the write
        // watermark callback brings us back here once it drains.
        if (evbuffer_get_length(bufferevent_get_output(bev)) > 0)
            return;

        _write_shutdown = true;
        if (fd != -1)
            ::shutdown(fd, SHUT_WR);

        if (_fin_sent)
            finish();
    }

    void TCPConnection::finish()
    {
        if (_finished)
            return;
        _finished = true;

        if (on_done)
            on_done();
    }

    void TCPConnection::stop_reading() { bufferevent_disable(bev, EV_READ); }

    void TCPConnection::resume_reading() { bufferevent_enable(bev, EV_READ); }

    TCPConnection::~TCPConnection()
    {
        // The stream can outlive us (the connection also holds it), so make sure nothing it does
        // afterwards calls back into this object.  These have to be cleared before the close below,
        // which can fire them re-entrantly.
        if (stream)
        {
            stream->set_data_callback(nullptr);
            stream->set_fin_callback(nullptr);
            stream->set_close_callback(nullptr);
            stream->disable_watermarks();

            // Being dropped without having finished (an owner tearing the tunnel down, or a connect
            // that failed outright) still has to take the stream down rather than leaving it open
            // on the wire.
            if (!_finished)
                stream->close(_connected ? tunnel_error::TCP_FAILURE : tunnel_error::CONNECT_FAILED);
        }

        bufferevent_free(bev);
        log::debug(logcat, "TCPSocket shut down!");
    }

    void TCPConnection::close(uint64_t ec)
    {
        if (_finished)
            return;

        log::debug(logcat, "TCP connection closing with application error code: {}", ec);
        stream->close(ec);
        finish();
    }

    std::shared_ptr<TCPHandle> TCPHandle::make_server(quic::Loop &ev, tcpconn_hook cb, uint16_t port)
    {
        std::shared_ptr<TCPHandle> h{new TCPHandle(ev, std::move(cb), port)};
        return h;
    }

    TCPHandle::TCPHandle(quic::Loop &ev_loop, tcpconn_hook cb, uint16_t p) : _ev{ev_loop}, _conn_maker{std::move(cb)}
    {
        if (!_conn_maker)
            throw std::logic_error{"TCPSocket construction requires a non-empty receive callback"};

        _init_server(p);
    }

    std::shared_ptr<TCPConnection> TCPHandle::connect(
        quic::Loop &ev, const quic::Address &dest, std::shared_ptr<quic::Stream> s)
    {
        // NB: BEV_OPT_THREADSAFE not used because this should only ever be touched
        // by a single thread.
        bufferevent *_bev = bufferevent_socket_new(ev.get_event_base(), -1, BEV_OPT_CLOSE_ON_FREE);
        if (!_bev)
        {
            log::warning(logcat, "Failed to create bufferevent for TCP connection to {}", dest);
            return nullptr;
        }

        auto tcp_conn = std::make_shared<TCPConnection>(_bev, -1, std::move(s));
        tcp_conn->_connected = false;

        bufferevent_setcb(_bev, tcp_read_cb, tcp_write_cb, tcp_event_cb, tcp_conn.get());
        bufferevent_enable(_bev, EV_READ | EV_WRITE);

        quic::Address target{dest};
        if (bufferevent_socket_connect(_bev, target, static_cast<int>(target.socklen())) < 0)
        {
            log::warning(logcat, "Failed to make bufferevent-based TCP connection to {}!", dest);
            return nullptr;
        }

        // only set after a call to bufferevent_socket_connect
        tcp_conn->fd = bufferevent_getfd(_bev);

        return tcp_conn;
    }

    void TCPHandle::_init_server(uint16_t port)
    {
        // Loopback only: the mapped port is for this device's applications, and the documented
        // establish_*() contract hands back a port on [::1].
        quic::Address bind_addr{"::1", port};

        _tcp_listener = _ev.template shared_ptr<struct evconnlistener>(
            evconnlistener_new_bind(
                _ev.get_event_base(),
                tcp_listen_cb,
                this,
                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE | LEV_OPT_REUSEABLE,
                -1,
                bind_addr,
                static_cast<int>(bind_addr.socklen())),
            evconnlistener_deleter);

        if (not _tcp_listener)
        {
            throw std::runtime_error{
                "TCP listener construction failed: {}"_format(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()))};
        }

        check_rv(getsockname(evconnlistener_get_fd(_tcp_listener.get()), _bound, _bound.socklen_ptr()));
        log::debug(logcat, "tcp listener, bound to {}", _bound);
        evconnlistener_set_error_cb(_tcp_listener.get(), tcp_err_cb);
    }

    TCPHandle::~TCPHandle()
    {
        _tcp_listener.reset();
        log::debug(logcat, "TCPHandle shut down!");
    }
}  //  namespace srouter
