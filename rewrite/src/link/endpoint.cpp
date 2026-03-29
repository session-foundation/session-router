#include <sr/link/endpoint.hpp>

// Layer 4: QUIC transport via oxen-libquic
//
// STATUS: Interface defined, implementation stubbed.
// The oxen-libquic API needs to be studied in detail to wire up:
// - Endpoint creation with proper ALPN strings
// - GnuTLS credential configuration
// - BTStream request/response handling
// - Datagram send/receive callbacks
// - Connection lifecycle management
//
// The headers (endpoint.hpp, manager.hpp) define the clean interface
// that Layer 5 (Node) will use. The implementation needs to map
// these to the actual oxen::quic::Endpoint, Connection, BTRequestStream,
// and Datagram APIs.

#include <mutex>
#include <unordered_map>

namespace sr::link {

using namespace sr::contact;

struct Endpoint::Impl {
    mutable std::mutex mtx;
    // TODO: oxen::quic::Endpoint, Loop, connection map
};

Endpoint::Endpoint(bool is_relay)
    : _is_relay{is_relay}, _impl{std::make_unique<Impl>()} {}

Endpoint::~Endpoint() { close(); }

void Endpoint::listen([[maybe_unused]] uint16_t port) {
    // TODO: create oxen::quic endpoint, bind, set ALPN
}

void Endpoint::connect([[maybe_unused]] const RouterID& rid,
                       [[maybe_unused]] const std::string& addr,
                       [[maybe_unused]] uint16_t port) {
    // TODO: establish QUIC connection with GnuTLS
}

void Endpoint::send_datagram([[maybe_unused]] const RouterID& to,
                             [[maybe_unused]] std::span<const std::byte> data) {
    // TODO: send via QUIC datagram channel
}

void Endpoint::send_request([[maybe_unused]] const RouterID& to,
                            [[maybe_unused]] std::string_view method,
                            [[maybe_unused]] std::span<const std::byte> payload,
                            [[maybe_unused]] std::function<void(std::span<const std::byte>)> on_response) {
    // TODO: send via BTStream
}

void Endpoint::on_datagram(DatagramHandler handler) {
    _dgram_handler = std::move(handler);
}

void Endpoint::on_request(BTStreamHandler handler) {
    _bt_handler = std::move(handler);
}

bool Endpoint::is_connected([[maybe_unused]] const RouterID& to) const {
    return false;  // TODO
}

size_t Endpoint::connection_count() const {
    return 0;  // TODO
}

std::vector<RouterID> Endpoint::connected_peers() const {
    return {};  // TODO
}

void Endpoint::disconnect([[maybe_unused]] const RouterID& rid) {
    // TODO
}

void Endpoint::close() {
    // TODO
}

}  // namespace sr::link
