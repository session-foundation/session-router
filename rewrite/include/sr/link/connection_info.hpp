#pragma once

#include <sr/contact/router_id.hpp>

#include <cstdint>
#include <memory>
#include <string>

// Forward declarations for oxen-quic types
namespace oxen::quic
{
    class Connection;
    class Datagrams;
    class BTRequestStream;
}  // namespace oxen::quic

namespace sr::link
{

    // Connection wrapper — holds a QUIC connection with its associated
    // datagrams handle and control stream.
    struct ConnectionInfo
    {
        sr::contact::RouterID rid;
        std::shared_ptr<oxen::quic::Connection> conn;
        std::shared_ptr<oxen::quic::Datagrams> datagrams;
        std::shared_ptr<oxen::quic::BTRequestStream> control_stream;
        std::string alpn;
        bool is_inbound = false;

        void close(uint64_t errcode = 0);
    };

}  // namespace sr::link
