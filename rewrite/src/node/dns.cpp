#include <arpa/inet.h>
#include <netinet/in.h>
#include <sr/node/dns.hpp>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace sr::node
{

    DnsResolver::~DnsResolver() { stop(); }

    bool DnsResolver::start(const std::string& bind_addr, uint16_t port, const std::string& upstream)
    {
        _upstream = upstream;

        _sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (_sock < 0)
            return false;

        struct sockaddr_in addr
        {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr);

        if (bind(_sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            ::close(_sock);
            _sock = -1;
            return false;
        }

        _running = true;
        return true;
    }

    void DnsResolver::stop()
    {
        _running = false;
        if (_sock >= 0)
        {
            ::close(_sock);
            _sock = -1;
        }
    }

    void DnsResolver::on_sesh_lookup(SeshLookupHandler handler) { _sesh_handler = std::move(handler); }

}  // namespace sr::node
