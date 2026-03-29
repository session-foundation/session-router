#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace sr::node {

// Minimal DNS resolver for .sesh TLD.
// Intercepts .sesh queries and resolves them to session-router addresses.
// Forwards all other queries to upstream DNS.

class DnsResolver {
public:
    DnsResolver() = default;
    ~DnsResolver();

    // Start listening for DNS queries
    bool start(const std::string& bind_addr, uint16_t port,
               const std::string& upstream);

    // Stop the resolver
    void stop();

    // Register a handler for .sesh lookups
    using SeshLookupHandler = std::function<std::string(const std::string& name)>;
    void on_sesh_lookup(SeshLookupHandler handler);

    bool is_running() const { return _running; }

private:
    int _sock = -1;
    bool _running = false;
    std::string _upstream;
    SeshLookupHandler _sesh_handler;
};

}  // namespace sr::node
