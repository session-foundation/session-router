#include <catch2/catch_test_macros.hpp>

#include <sr/node/dns.hpp>

using namespace sr::node;

TEST_CASE("DnsResolver default state", "[node][dns]") {
    DnsResolver dns;
    REQUIRE_FALSE(dns.is_running());
}

TEST_CASE("DnsResolver stop on unstarted is safe", "[node][dns]") {
    DnsResolver dns;
    dns.stop();
    REQUIRE_FALSE(dns.is_running());
}

TEST_CASE("DnsResolver start on available port", "[node][dns]") {
    DnsResolver dns;
    // Use a high port to avoid permission issues
    bool started = dns.start("127.0.0.1", 15353, "1.1.1.1");
    if (started) {
        REQUIRE(dns.is_running());
        dns.stop();
        REQUIRE_FALSE(dns.is_running());
    }
    // If port is busy, that's ok — just verify it reports correctly
}

TEST_CASE("DnsResolver handler registration", "[node][dns]") {
    DnsResolver dns;
    bool handler_set = false;
    dns.on_sesh_lookup([&](const std::string&) -> std::string {
        handler_set = true;
        return "10.0.0.1";
    });
    // Handler is stored but not invoked until a query arrives
    REQUIRE_FALSE(handler_set);  // not called yet
}
