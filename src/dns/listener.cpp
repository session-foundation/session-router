#include "listener.hpp"

#include "router/router.hpp"
#include "util/logging.hpp"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <oxenc/endian.h>

namespace srouter::dns
{
    namespace
    {
        auto logcat = log::Cat("dns");

        struct tcp_conn
        {
            Listener& listener;
            bufferevent* bev;
            quic::Address addr;
            // This gets shared with the handler callback so that we can tell if the raw tcp_conn
            // pointer is still valid:
            std::shared_ptr<bool> alive = std::make_shared<bool>(true);

            tcp_conn(Listener& l, bufferevent* b, sockaddr* src, int socklen)
                : listener{l}, bev{b}, addr{src, static_cast<socklen_t>(socklen)}
            {}

            void close()
            {
                bufferevent_free(bev);
                bev = nullptr;
            }

            ~tcp_conn() { *alive = false; }
        };

    }  // namespace

    void Listener::evconnlistener_deleter::operator()(::evconnlistener* e)
    {
        if (e)
            evconnlistener_free(e);
    }

    Listener::Listener(Router& router, const quic::Address& bind) : _handler{router} { listen(router.loop(), bind); }

    struct Listener::udp_socket_helper
    {
        std::unique_ptr<quic::UDPSocket> sock;
    };

    // Defaulted, but here because the header doesn't have visibility into the predeclared unique_ptrs
    Listener::~Listener() = default;

    void Listener::listen(quic::Loop& loop, const quic::Address& bind)
    {
        // call_get this so that we can be sure that the callbacks defined here can't be called
        // before we are done setting it up:
        loop.call_get([&] {
            auto h = std::make_unique<udp_socket_helper>();

            h->sock = std::make_unique<quic::UDPSocket>(
                loop.get_event_base(), bind, quic::UDPSocket::options{}, [this, h = h.get()](quic::Packet&& pkt) {
                    if (pkt.path.remote == pkt.path.local)
                    {
                        log::warning(logcat, "DNS packet loop detected: ignoring UDP DNS request");
                        return;
                    }
                    log::trace(logcat, "Incoming DNS UDP packet from {}", pkt.path.remote);

                    // We don't need to worry about keep-alive here because we own the handler, and
                    // so if it's calling something then `this` must still be alive.
                    _handler(
                        pkt.data(),
                        pkt.path.remote,
                        [path = pkt.path, udp = h->sock.get()](std::span<const std::byte> payload) {
                            const size_t sz = payload.size();
                            const uint8_t ecn = 0;
                            // A reply has to come from the address the query was sent to.
                            udp->send(path, payload.data(), &sz, &ecn, 1, /*pin_source=*/true);
                        });
                });
            last_port = h->sock->address().port();
            _udp.push_back(std::move(h));

            _tcp.emplace_back(evconnlistener_new_bind(
                loop.get_event_base(),
                [](evconnlistener* listener, evutil_socket_t fd, sockaddr* src, int socklen, void* ctx) {
                    auto* bev = bufferevent_socket_new(evconnlistener_get_base(listener), fd, BEV_OPT_CLOSE_ON_FREE);
                    auto* c = new tcp_conn{*static_cast<Listener*>(ctx), bev, src, socklen};

                    log::trace(logcat, "Incoming DNS TCP connection from {}", c->addr);

                    bufferevent_setcb(
                        bev,
                        [](bufferevent* bev, void* ctx) {
                            // read callback
                            auto* in = bufferevent_get_input(bev);
                            while (true)
                            {
                                log::trace(logcat, "Incoming DNS TCP data");
                                uint16_t reqlen;
                                if (evbuffer_copyout(in, &reqlen, 2) < 2)
                                    break;
                                oxenc::big_to_host_inplace(reqlen);
                                log::trace(logcat, "Incoming DNS TCP request of size {}", reqlen);
                                size_t pending = evbuffer_get_length(in) - 2;
                                if (pending < reqlen)
                                {
                                    // We don't have enough of the request yet, so leave the buffer
                                    // as-is: libevent won't call us again until more data arrives,
                                    // and will just leave the current buffer data in place.
                                    log::trace(
                                        logcat,
                                        "Not enough TCP data ({}) for request body ({}); delaying processing until we "
                                        "get more",
                                        pending,
                                        reqlen);
                                    break;
                                }
                                std::vector<std::byte> req;
                                req.resize(reqlen);
                                evbuffer_drain(in, 2);
                                evbuffer_remove(in, req.data(), reqlen);
                                log::trace(logcat, "Read {}-byte TCP DNS request", req.size());

                                auto* c = static_cast<tcp_conn*>(ctx);
                                c->listener._handler(
                                    req,
                                    c->addr,
                                    [c, alive = c->alive](std::span<const std::byte> payload) {
                                        if (!*alive)
                                            return;
                                        auto* out = bufferevent_get_output(c->bev);
                                        // The only difference between UDP DNS and TCP DNS encoding is that
                                        // UDP is per-packet, but TCP is a stream of messages where each
                                        // message is prefixed with the length of the message:
                                        uint16_t size = oxenc::host_to_big(static_cast<uint16_t>(payload.size()));
                                        if (evbuffer_add(out, &size, 2) == -1
                                            || evbuffer_add(out, payload.data(), payload.size()) == -1)
                                        {
                                            log::warning(logcat, "Failed to write response to TCP connection; closing");
                                            bufferevent_free(c->bev);
                                            delete c;
                                        }
                                    },
                                    true);
                            }
                        },
                        nullptr,
                        [](bufferevent* bev, short events, void* ctx) {
                            auto* c = static_cast<tcp_conn*>(ctx);
                            // event callback
                            if (events & BEV_EVENT_EOF)
                                log::debug(logcat, "UDP TCP connection from {} closed by peer", c->addr);
                            if (events & BEV_EVENT_ERROR)
                                log::debug(
                                    logcat,
                                    "UDP TCP connection from {} closed by error: {}",
                                    c->addr,
                                    evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
                            if (events & BEV_EVENT_TIMEOUT)
                                // Is this even possible on a listening socket?
                                log::debug(logcat, "UDP TCP connection from {} timed out", c->addr);

                            if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
                            {
                                bufferevent_free(bev);
                                delete c;
                            }
                        },
                        c);

                    bufferevent_enable(bev, EV_READ | EV_WRITE);
                },
                this,
                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                -1,
                bind,
                static_cast<int>(bind.socklen())));

            log::debug(logcat, "session-router DNS listening on {}", bind);
        });
    }

}  // namespace srouter::dns
