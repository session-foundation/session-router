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

    class QUICTunnel;

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

        std::vector<std::byte> pending_buffer;

        void on_stream_data(quic::Stream& stream, std::span<const std::byte> data);

        void close(uint64_t ec = 0);

        void on_write_available();

        void stop_reading();
        void resume_reading();
    };

    using tcpconn_hook = std::function<TCPConnection*(bufferevent*, TCPConnection::fd_t)>;

    class TCPHandle
    {
        using socket_t =
#ifndef _WIN32
            int
#else
            SOCKET
#endif
            ;

        quic::Loop& _ev;
        std::shared_ptr<::evconnlistener> _tcp_listener;

        // The OutboundSession will set up an evconnlistener and set the listening socket address inside ::_bound
        quic::Address _bound{};

        // The InboundSession will set this address to the session-router-primary-ip to connect to
        std::optional<quic::Address> _connect = std::nullopt;

        socket_t _sock;

        explicit TCPHandle(quic::Loop& ev, tcpconn_hook cb, uint16_t p);

        explicit TCPHandle(quic::Loop& ev, quic::Address connect);

      public:
        TCPHandle() = delete;

        tcpconn_hook _conn_maker;

        // The OutboundSession object will hold a server listening on some localhost:port, returning that port to the
        // application for it to make a TCP connection
        static std::shared_ptr<TCPHandle> make_server(quic::Loop& ev, tcpconn_hook cb, uint16_t port = 0);

        // The InboundSession object will hold a client that connects to some application configured
        // session-router-primary-ip:port every time the OutboundSession opens a new stream over the tunneled connection
        static std::shared_ptr<TCPHandle> make_client(quic::Loop& ev, quic::Address connect);

        ~TCPHandle();

        uint16_t port() const { return _bound.port(); }

        const quic::Address& bind_address() const { return _bound; }

        static std::shared_ptr<TCPConnection> connect(
            event_base* _ev, quic::Address src, std::shared_ptr<quic::Stream> s, uint16_t port);

      private:
        void _init_client();

        void _init_server(uint16_t port);
    };
}  //  namespace srouter
