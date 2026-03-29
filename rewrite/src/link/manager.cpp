#include <sr/link/manager.hpp>

namespace sr::link
{

    using namespace sr::contact;

    Manager::Manager(Endpoint& endpoint) : _endpoint{endpoint}
    {
        // Wire up the dispatch
        _endpoint.on_request([this](
                                 const RouterID& from,
                                 std::string_view method,
                                 std::span<const std::byte> payload,
                                 std::function<void(std::vector<std::byte>)> respond) {
            dispatch_request(from, method, payload, std::move(respond));
        });
    }

    void Manager::on(const std::string& method, MessageHandler handler) { _handlers[method] = std::move(handler); }

    void Manager::on_datagram(DatagramHandler handler) { _endpoint.on_datagram(std::move(handler)); }

    void Manager::send_datagram(const RouterID& to, std::span<const std::byte> data)
    {
        _endpoint.send_datagram(to, data);
    }

    void Manager::send_request(
        const RouterID& to,
        std::string_view method,
        std::span<const std::byte> payload,
        std::function<void(std::span<const std::byte>)> on_response)
    {
        _endpoint.send_request(to, method, payload, std::move(on_response));
    }

    void Manager::connect(const RouterID& rid, const std::string& addr, uint16_t port)
    {
        _endpoint.connect(rid, addr, port);
    }

    bool Manager::is_connected(const RouterID& to) const { return _endpoint.is_connected(to); }

    std::vector<RouterID> Manager::connected_peers() const { return _endpoint.connected_peers(); }

    void Manager::dispatch_request(
        const RouterID& from,
        std::string_view method,
        std::span<const std::byte> payload,
        std::function<void(std::vector<std::byte>)> respond)
    {
        auto it = _handlers.find(std::string{method});
        if (it != _handlers.end())
        {
            it->second(from, payload, std::move(respond));
        }
        // Unknown methods silently dropped — relay behavior
    }

}  // namespace sr::link
