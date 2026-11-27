#pragma once

#include "address/ip_range.hpp"
#include "config/config.hpp"
#include "router/route_poker.hpp"
#include "rpc_request_decorators.hpp"

#include <oxen/log/omq_logger.hpp>
#include <oxenmq/address.h>
#include <oxenmq/oxenmq.h>

#include <string_view>
#include <unordered_map>
#include <vector>

namespace srouter::rpc
{
    //  RPC: halt
    //    Stops Session Router router
    //
    //  Inputs: none
    //
    struct Halt : NoArgs, Immediate
    {
        static constexpr auto name = "halt"sv;
    };

    //  RPC: version
    //    Returns version and uptime information
    //
    //  Inputs: none
    //
    //  Returns: "OK"
    //    "uptime"
    //    "version"
    //
    struct Version : NoArgs, Immediate
    {
        static constexpr auto name = "version"sv;
    };

    //  RPC: status
    //    Returns that current activity status of Session Router router
    //    Calls router::extractstatus
    //
    //  Inputs: none
    //
    //  Returns: massive dump of status info
    //
    struct Status : NoArgs
    {
        static constexpr auto name = "status"sv;
    };

    //  RPC: get_status
    //    Returns current summary status
    //
    //  Inputs: none
    //
    //  Returns: slightly smaller dump of status info including
    //    "authcodes"
    //    "exitMap"
    //    "lokiAddress"
    //    "networkReady"
    //    "numPathsBuilt"
    //    "numPeersConnected"
    //    etc
    //
    struct GetStatus : NoArgs
    {
        static constexpr auto name = "get_status"sv;
    };

    //  RPC: quic_connect
    //    Initializes QUIC connection tunnel
    //    Passes request parameters in nlohmann::json format
    //
    //  Inputs:
    //    "endpoint" : endpoint id (string)
    //    "bindAddr" : bind address (string, ex: "127.0.0.1:1142")
    //    "host" : remote host ID (string)
    //    "port" : port to bind to (int)
    //    "close" : close connection to port or host ID
    //
    //  Returns:
    //    "id" : connection ID
    //    "addr" : connection local address
    //
    struct QuicConnect : RPCRequest
    {
        static constexpr auto name = "quic_connect"sv;

        struct request_parameters
        {
            std::string bindAddr;
            int closeID;
            std::string endpoint;
            uint16_t port;
            std::string remoteHost;
        } request;
    };

    //  RPC: quic_listener
    //    Connects to QUIC interface on local endpoint
    //    Passes request parameters in nlohmann::json format
    //
    //  Inputs:
    //    "endpoint" : endpoint id (string)
    //    "host" : remote host ID (string)
    //    "port" : port to bind to (int)
    //    "close" : close connection to port or host ID
    //    "srv-proto" :
    //
    //  Returns:
    //    "id" : connection ID
    //    "addr" : connection local address
    //
    struct QuicListener : RPCRequest
    {
        static constexpr auto name = "quic_listener"sv;

        struct request_parameters
        {
            int closeID;
            std::string endpoint;
            uint16_t port;
            std::string remoteHost;
            std::string srvProto;
        } request;
    };

    //  RPC: lookup_snode
    //    Look up service node
    //    Passes request parameters in nlohmann::json format
    //
    //  Inputs:
    //    "routerID" : router ID to query (string)
    //
    //  Returns:
    //    "ip" : snode IP address
    //
    struct LookupSnode : RPCRequest
    {
        static constexpr auto name = "lookup_snode"sv;

        struct request_parameters
        {
            std::string routerID;
        } request;
    };

    //  RPC: map_exit
    //    Map a new connection to an exit node
    //
    //  Inputs:
    //    "address" : ID of endpoint to map
    //    "range" : IP range to map to exit node
    //    "token" : auth token
    //
    //  Returns:
    //
    struct MapExit : RPCRequest
    {
        static constexpr auto name = "map_exit"sv;

        struct request_parameters
        {
            std::string address;
            bool full_tunnel{false};
            std::vector<std::string> ip_ranges;
            std::string token;
        } request;
    };

    //  RPC: list_exits
    //    List all currently mapped exit node connections
    //
    //  Inputs: none
    //
    //  Returns:
    //
    struct ListExits : NoArgs
    {
        static constexpr auto name = "list_exits"sv;
    };

    //  RPC: first_hops
    //    The IP addresses of the relays this router talks to directly: established outbound
    //    connections and dials in progress.  Meant for something that manages routes itself (with
    //    [network]:auto-routing=false), so it can keep these addresses on the physical uplink and
    //    the router's own traffic never loops back into its tunnel.  The list changes as
    //    connections come and go, so poll it.
    //
    //  Inputs: none
    //
    //  Returns: { "first_hops": ["203.0.113.7", "2001:db8::1", ...] }
    //
    struct FirstHops : NoArgs
    {
        static constexpr auto name = "first_hops"sv;
    };

    //  RPC: unmap_exit
    //    Unmap a connection to an exit node
    //
    //  Inputs:
    //    "endpoint" : ID of endpoint to map
    //
    //  Returns:
    //
    struct UnmapExit : RPCRequest
    {
        static constexpr auto name = "unmap_exit"sv;

        struct request_parameters
        {
            std::string address;
        } request;
    };

    //  RPC: swap_exit
    //    Swap a connection from one exit to another
    //
    //  Inputs:
    //    "exits" : exit nodes to swap mappings from (index 0 = old exit, index 1 = new exit)
    //
    //  Returns:
    //
    struct SwapExits : RPCRequest
    {
        static constexpr auto name = "swap_exits"sv;

        struct request_parameters
        {
            std::vector<std::string> exit_addresses;
            bool full_tunnel{false};
            std::vector<std::string> ip_ranges;
            std::string token;
        } request;
    };

#if 0
    //  RPC: dns_query
    //    Attempts to query endpoint by domain name
    //
    //  Inputs:
    //    "endpoint" : endpoint ID to query (string)
    //    "qname" : query name (string)
    //    "qtype" : query type (int)
    //
    //  Returns:
    //
    struct DNSQuery : Immediate
    {
        static constexpr auto name = "dns_query"sv;

        struct request_parameters
        {
            std::string endpoint;
            uint16_t qtype;
            std::string qname;
        } request;
    };
#endif

    //  RPC: find_cc
    //    Lookup client contact via path request
    //
    //  Inputs:
    //    "pk" : client pubkey
    //
    //  Returns:
    //    "cc" : client contact, or error string
    struct FindCC : RPCRequest
    {
        static constexpr auto name = "find_cc"sv;

        struct request_parameters
        {
            std::string pk;
        } request;
    };

    //  RPC: session_init
    //    Initiate session to remote instance
    //
    //  Inputs:
    //    "pk" : remote pubkey (with .sesh or .snode on the end)
    //
    //  Returns:
    //    "ip" : mapped IP address, or error string
    struct SessionInit : RPCRequest
    {
        static constexpr auto name = "session_init"sv;

        struct request_parameters
        {
            std::string pk;
        } request;
    };

    //  RPC: session_close
    //    Close session to remote instance
    //
    //  Inputs:
    //    "pk" : remote pubkey
    //
    //  Returns:
    //    "b" : T/F if close was successful
    struct SessionClose : RPCRequest
    {
        static constexpr auto name = "session_close"sv;

        struct request_paramters
        {
            std::string pk;
        } request;
    };

    // List of all RPC request structs to allow compile-time enumeration of all supported types
    using rpc_request_types = tools::type_list<
        Halt,
        Version,
        Status,
        GetStatus,
        QuicConnect,   // debug
        QuicListener,  // debug
        LookupSnode,
        FindCC,
        SessionInit,
        SessionClose,
        MapExit,
        ListExits,
        FirstHops,
        SwapExits,
        UnmapExit>;

}  // namespace srouter::rpc
