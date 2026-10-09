#pragma once

#include <oxen/quic/loop.hpp>
#include <oxen/quic/stream.hpp>

extern "C"
{
#include <arpa/inet.h>
    struct bufferevent;
    struct evconnlistener;
}

namespace srouter
{
    namespace quic = oxen::quic;

    // Application error codes used when closing a tunnelled stream.  These stay well clear of
    // libquic's own error codes (which start at 777'000'000) so that a close code identifies
    // unambiguously whether the tunnel or the QUIC layer ended the stream.
    namespace tunnel_error
    {
        // The local TCP connection failed (as opposed to closing cleanly, which sends a FIN).
        inline constexpr uint64_t TCP_FAILURE = 0x5471909;
        // The accepting end could not establish a TCP connection to the requested port.
        inline constexpr uint64_t CONNECT_FAILED = 0x5471907;
        // The accepting end declined to connect to the requested port.
        inline constexpr uint64_t REFUSED = 0x547190a;
    }  // namespace tunnel_error

    struct TCPConnection
    {
        // This should be a evutil_socket_t; we check in the .cpp:
#ifdef _WIN32
        using fd_t = intptr_t;
#else
        using fd_t = int;
#endif

        TCPConnection(bufferevent* _bev, fd_t _fd, std::shared_ptr<quic::Stream> _s);

        TCPConnection() = delete;

        /// Non-copyable and non-moveable
        TCPConnection(const TCPConnection& s) = delete;
        TCPConnection& operator=(const TCPConnection& s) = delete;
        TCPConnection(TCPConnection&& s) = delete;
        TCPConnection& operator=(TCPConnection&& s) = delete;

        ~TCPConnection();

        bufferevent* bev;
        fd_t fd;

        std::shared_ptr<quic::Stream> stream;

        // Invoked once, when both directions have finished or either end failed, to tell the owner
        // to drop this connection.  This can fire from inside a bufferevent or stream callback, so
        // the owner must defer the destruction rather than doing it during the call.
        std::function<void()> on_done;

        // Ends the connection.  A zero code closes the stream cleanly; any other code is delivered
        // to the far end to distinguish a failure from an orderly shutdown.
        void close(uint64_t ec = 0);

        void on_write_available();

        void stop_reading();
        void resume_reading();

        // The local TCP side finished sending (a clean EOF); passes the half-close on to the far end
        // and leaves the other direction running.
        void on_tcp_eof();

        // The far end finished sending; shuts down our write side once anything still buffered for
        // the application has drained.
        void on_stream_fin();

        // False only between starting an outgoing connection and it completing, so that a failure
        // during that window is reported as "could not connect" rather than "connection broke".
        bool _connected{true};

        bool _finished{false};
        bool _fin_sent{false};
        bool _fin_received{false};
        bool _write_shutdown{false};

        void finish();
        void flush_and_shutdown_write();
    };

    using tcpconn_hook = std::function<TCPConnection*(bufferevent*, TCPConnection::fd_t)>;

    class TCPHandle
    {
        quic::Loop& _ev;
        std::shared_ptr<::evconnlistener> _tcp_listener;

        // The address the listener is bound to, filled in from the socket once it is listening.
        quic::Address _bound{};

        explicit TCPHandle(quic::Loop& ev, tcpconn_hook cb, uint16_t p);

      public:
        TCPHandle() = delete;

        tcpconn_hook _conn_maker;

        // Listens on the IPv6 loopback address for the initiating side of a tunnel, returning the
        // bound port for the application to connect to.  Port 0 (the default) takes any free port.
        static std::shared_ptr<TCPHandle> make_server(quic::Loop& ev, tcpconn_hook cb, uint16_t port = 0);

        ~TCPHandle();

        uint16_t port() const { return _bound.port(); }

        const quic::Address& bind_address() const { return _bound; }

        // Used by the accepting side of a tunnel: connects to `dest` and pairs the resulting socket
        // with `s`.  The stream should be paused until the connection completes, which the returned
        // connection signals by resuming it.  Returns nullptr if the connection could not be started.
        static std::shared_ptr<TCPConnection> connect(
            quic::Loop& ev, const quic::Address& dest, std::shared_ptr<quic::Stream> s);

      private:
        void _init_server(uint16_t port);
    };
}  //  namespace srouter
