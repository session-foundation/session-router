#pragma once

#include "message.hpp"
#include "unbound.hpp"

#include <oxen/quic/address.hpp>
#include <oxen/quic/loop.hpp>

namespace srouter
{
    class Router;
    namespace quic = oxen::quic;
}  // namespace srouter

namespace srouter::dns
{
    class RequestHandler
    {
      public:
        using ReplyCallback = std::function<void(std::span<const std::byte> response)>;

        explicit RequestHandler(Router& router);

        // Called when a request arrives to process the request; when the answer is ready, calls
        // `reply()` with it.  If tcp is true then we allow up to 64k for the response, otherwise
        // the max size is dependent on the DNS message itself.
        void operator()(
            std::span<const std::byte> request, const quic::Address& from, ReplyCallback reply, bool tcp = false);

      private:
        // Secret value we use as a key in DNS server cookie hashing.  We generate a random once on
        // each startup as we currently have no need for this to be deterministic, and that
        // regeneration also provides DNS cookie key rotation whenever we restart.
        std::array<std::byte, 16> _cookie_secret;

        Router& _router;

        // Our unbound object for handling upstream DNS requests.  Normally present, but can be
        // explicitly disable in the config.  If unset, we return REFUSED if called upon to resolve
        // something outside of Session Router domains.
        std::optional<Unbound> _unbound;

        // Our serial for SOA records (typically only included for negative responses, i.e.
        // something we are responsible for that doesn't exist).  We increment this every time it is
        // used to avoid caching issues.
        uint32_t _soa_serial = 1;

        // Called to check if the request is for a local name (i.e. .sesh, .snode, .loki, or a PTR
        // record for one of the addresses in our tun).  If so, this handles the request and returns
        // true; otherwise returns false.
        bool handle_local(ReplyCallback& reply, Message& msg, std::string qname, bool tcp);

        // Checks for PTR for a range we own, and if so, replies and returns true.  Returns false if
        // not a PTR for us (i.e. the caller should continue processing).
        bool handle_local_ptr(Message& m, ReplyCallback& reply, bool tcp);

        // Answers the question recursively via our configured upstream DNS servers (if any)
        void forward(Message&& m, ReplyCallback&& reply, bool tcp);

        // Adds an SOA authority record to the message; generally you should only do this for
        // negative replies (i.e. record does not exist) when you want the lack of record to be
        // cachable for up to `ttl`.  Including it in other responses is pointless: positive results
        // have their own TTL, and not including an SOA should prevent caching.
        void add_nx_soa(Message& m, std::string domain, std::chrono::seconds ttl);
    };

}  // namespace srouter::dns
