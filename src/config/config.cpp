#include "config.hpp"

#include "constants/path.hpp"
#include "constants/platform.hpp"
#include "constants/version.hpp"
#include "contact/sns.hpp"
#include "definition.hpp"
#include "ini.hpp"
#include "path/path_handler.hpp"
#include "util/file.hpp"
#include "util/formattable.hpp"
#include "util/logging/buffer.hpp"

#include <filesystem>
#include <stdexcept>

namespace srouter
{
    static auto logcat = log::Cat("config");

    using namespace config;

    static auto public_ip_loader(std::optional<quic::Address>& into, std::string conf_name)
    {
        return [&into, conf_name = std::move(conf_name)](std::string ip) {
            try
            {
                quic::Address a{ip, into ? into->port() : uint16_t{0}};

                if (!a.is_ipv4())
                    throw std::invalid_argument{"IP must be an IPv4 address"};
                if (!a.is_public_ip())
                    throw std::invalid_argument{"IP is not public"};

                into = std::move(a);
            }
            catch (const std::exception& e)
            {
                throw std::invalid_argument{"Invalid {}: {}"_format(conf_name, e.what())};
            }
        };
    }
    static auto public_port_loader(std::optional<quic::Address>& into, std::string conf_name)
    {
        return [&into, conf_name = std::move(conf_name)](uint16_t port) {
            if (port == 0)
                throw std::invalid_argument{"{} cannot be 0"_format(conf_name)};
            if (!into)
                into.emplace();
            into->set_port(port);
        };
    }

    void RouterConfig::define_config_options(ConfigDefinition& conf)
    {
        is_relay = conf.type == config::Type::Relay;

        conf.add_section_comments(
            "router",
            {
                "Configuration for routing activity.",
            });

        conf.define_option<std::string>(
            "router",
            "netid",
            Default{"{}"_format(NetID::MAINNET)},
            Comment{"Network ID; this is '{}' for mainnet, '{}' for testnet."_format(NetID::MAINNET, NetID::TESTNET)},
            [this](std::string arg) { net_id = netid_from_string(arg); });

        conf.define_option<std::filesystem::path>(
            "router",
            "data-dir",
            Comment{
                "Directory in which to store Session Router runtime data such as router contact info",
                "and connection data.  If not specified, the default is to use the directory containing",
                "the config file specified when starting Session Router.",
            },
            [this](std::filesystem::path arg) {
                if (arg.empty())
                    arg = std::filesystem::path{"."};
                if (not exists(arg))
                    if (std::error_code ec; not create_directories(arg, ec))
                        throw std::runtime_error{
                            "Specified [router]:data-dir {} does not exist, and could not be created ({})"_format(
                                arg, ec.message())};

                data_dir = std::move(arg);
            });

        conf.define_option<std::string>(
            "router",
            "public-ip",
            RelayOnly,
            Comment{
                "For complex network configurations where the detected IP is incorrect or non-public",
                "this setting specifies the public IPv4 address at which this router reachable.",
            },
            public_ip_loader(public_addr, "[router]:public-address"));

        conf.define_option<std::string>("router", "public-address", Hidden, [](std::string) {
            throw std::invalid_argument{
                "[router]:public-address option no longer supported, use [router]:public-ip and "
                "[router]:public-port instead"};
        });

        conf.define_option<uint16_t>(
            "router",
            "public-port",
            RelayOnly,
            Comment{
                "When specifying public-ip=, this specifies the public UDP port at which this Session Router",
                "router is reachable. Defaults to the [bind]:listen port when public-ip is specified.",
            },
            public_port_loader(public_addr, "[router]:public-port"));

        conf.add_options_validator([this] {
            if (public_addr and not public_addr->is_public_ip())
                throw std::invalid_argument{"[router]:public-ip is required when specifying [router]:public-port"};
        });

        // Hidden option because this isn't something that should ever be turned off occasionally
        // when doing dev/testing work.
        conf.define_option<bool>("router", "block-bogons", Default{true}, Hidden, assignment_acceptor(block_bogons));
    }

    void ExitConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.define_option<std::string>(
            "exit",
            "auth",
            FullClientOnly,
            MultiValue,
            Comment{
                "Specify an optional authentication token required to use a non-public exit node.",
                "For example:",
                "    auth=myfavouriteexit.{}:abc"_format(CLIENT_TLD),
                "uses the authentication code `abc` whenever myfavouriteexit.{} is accessed."_format(CLIENT_TLD),
                "Can be specified multiple times to store codes for different exit nodes.  The",
                ".{} name may also be replaced with a .loki ONS name."_format(CLIENT_TLD),
            },
            [this](std::string arg) {
                if (arg.empty())
                {
                    sns_auth_tokens.clear();
                    auth_tokens.clear();
                    return;
                }

                const auto pos = arg.find(":");

                if (pos == std::string::npos)
                {
                    throw std::invalid_argument{
                        "[exit]:auth invalid format, expects exit-address.{}:auth-token-goes-here"_format(CLIENT_TLD)};
                }

                const auto addr = arg.substr(0, pos);
                auto auth = arg.substr(pos + 1);

                if (is_valid_sns(addr))
                {
                    sns_auth_tokens.emplace(std::move(addr), std::move(auth));
                    return;
                }
                try
                {
                    NetworkAddress exit{addr};
                    if (!exit.client())
                        throw std::invalid_argument{
                            "only .{}/.loki addresses can be used for exits"_format(CLIENT_TLD)};
                    auth_tokens.emplace(std::move(exit), std::move(auth));
                }
                catch (const std::exception& e)
                {
                    throw std::invalid_argument("[exit]:auth invalid exit address: {}"_format(e.what()));
                }
            });

        conf.define_option<bool>(
            "exit",
            "enable",
            FullClientOnly,
            Default{false},
            assignment_acceptor(exit_enabled),
            Comment{
                "Enable exit-node functionality for local Session Router instance.",
            });

        conf.define_option<std::string>(
            "exit",
            "policy",
            FullClientOnly,
            MultiValue,
            Comment{
                "Specifies the IP traffic accepted by the local exit node traffic policy. If any are",
                "specified then only matched traffic will be allowed and all other traffic will be",
                "dropped. Examples:",
                "    policy=tcp",
                "would allow all TCP/IP packets (regardless of port);",
                "    policy=0x69",
                "would allow IP traffic with IP protocol 0x69;",
                "    policy=udp/53",
                "would allow UDP port 53; and",
                "    policy=tcp/smtp",
                "would allow TCP traffic on the standard smtp port (21).",
            },
            [this](std::string arg) {
                if (arg.empty())
                {
                    exit_policy.protocols.clear();
                    return;
                }
                // this will throw on error
                exit_policy.protocols.insert(net::ProtocolInfo::from_config(arg));
            });

        conf.define_option<std::string>(
            "exit",
            "reserved-range",
            FullClientOnly,
            MultiValue,
            Comment{
                "Reserve an ip range to use as an exit broker for a `.{}` address"_format(CLIENT_TLD),
                "Specify a `.{}` address and a reserved ip range to use as an exit broker."_format(CLIENT_TLD),
                "Examples:",
                "    reserved-range=whatever.{}"_format(CLIENT_TLD),
                "would route all exit traffic through whatever.{}; and"_format(CLIENT_TLD),
                "    reserved-range=stuff.{}:100.0.0.0/24"_format(CLIENT_TLD),
                "would route the IP range 100.0.0.0/24 through stuff.{}."_format(CLIENT_TLD),
                "This option can be specified multiple times (to map different IP ranges).",
            },
            [this](std::string arg) {
                if (arg.empty())
                    return;

                std::variant<ipv4_range, ipv6_range> range;

                const auto pos = arg.find(":");

                if (pos == std::string::npos)
                    range = ipv4{0} / 0;
                else
                {
                    try
                    {
                        std::string input = arg.substr(pos + 1);
                        if (input.find(":") != std::string::npos)  // ipv6
                            range = parse_ipv6_range(input, 128);
                        else
                            range = parse_ipv4_range(input, 32);
                    }
                    catch (const std::exception& e)
                    {
                        throw std::invalid_argument{"[exit]:reserved-range invalid ip range: {}"_format(e.what())};
                    }

                    arg.resize(pos);
                }

                if (is_valid_sns(arg))
                    sns_ranges[arg].push_back(std::move(range));
                else
                {
                    try
                    {
                        ranges[NetworkAddress{arg}].push_back(std::move(range));
                    }
                    catch (const std::exception& e)
                    {
                        throw std::invalid_argument{"[exit]:reserved-range invalid address: {}"_format(arg)};
                    }
                }
            });

        conf.define_option<std::string>(
            "exit",
            "routed-range",
            FullClientOnly,
            MultiValue,
            Comment{
                "Advertise that exit node routes exit traffic to the specified IP range. If omitted, the",
                "default is ALL public ranges.  Can be set to public to indicate that this exit",
                "routes traffic to the public internet.",
                "For example:",
                "    routed-range=10.0.0.0/16",
                "    routed-range=public",
                "to advertise that this exit routes traffic to both the public internet, and to",
                "10.0.x.y addresses.",
                "",
                "Note that this option does not automatically configure network routing; that",
                "must be configured separately on the exit system to handle Session Router traffic.",
            },
            [this](std::string arg) {
                if (arg == "public")
                    exit_policy.ranges.push_back(ipv4{0} / 0);
                else
                {
                    try
                    {
                        if (arg.find(':') != std::string::npos)
                            exit_policy.ranges_v6.push_back(parse_ipv6_range(arg, 128));
                        else
                            exit_policy.ranges.push_back(parse_ipv4_range(arg, 32));
                    }
                    catch (const std::exception& e)
                    {
                        throw std::invalid_argument{"[exit]:routed-range invalid range '{}': {}"_format(arg, e.what())};
                    }
                }
            });
    }

    void NetworkConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.add_section_comments(
            "network",
            {
                "Network settings related to network devices and communications.",
            });

        conf.define_option<bool>(
            "network",
            "save-profiles",
            Default{conf.type != config::Type::EmbeddedClient},
            Hidden,
            assignment_acceptor(save_profiles));

        conf.define_option<bool>("network", "profiling", Default{true}, Hidden, assignment_acceptor(enable_profiling));

        conf.define_option<std::filesystem::path>(
            "network",
            "keyfile",
            ClientOnly,
            [this, rel_base = conf.conf_dir](std::filesystem::path arg) {
                if (arg.empty())
                {
                    keyfile.reset();
                    return;
                }
                if (arg.is_relative())
                    arg = rel_base / arg;
                if (!exists(arg))
                    throw std::invalid_argument{"cannot load key file {}: file not found"_format(arg)};
                log::info(logcat, "Client configured to use private key file {}", arg);
                keyfile.emplace(std::move(arg));
            },
            Comment{
                "Filename of a persistent, private key to use on the network.  If not specified a",
                "different random address will be used each time Session Router restarts.",
                "",
                "The session-router-config program can be used to generate such a key file.",
            });

        conf.define_option<std::string>(
            "network",
            "auth-type",
            FullClientOnly,
            Comment{
                "Set the endpoint authentication type.",
                "none/whitelist/lmq/file",
            },
            [this](std::string arg) {
                if (arg == "file")
                    auth_type = auth::AuthType::FILE;
                else if (arg == "lmq" || arg == "omq" || arg == "zmq")
                    auth_type = auth::AuthType::OMQ;
                else if (arg == "whitelist")
                    auth_type = auth::AuthType::WHITELIST;
                else if (arg == "" || arg == "none")
                    auth_type = auth::AuthType::NONE;
                else
                    throw std::invalid_argument{"invalid [network]:auth-type value: '{}'"_format(arg)};
            });

        conf.define_option<std::string>(
            "network",
            "omq-auth-endpoint",
            FullClientOnly,
            assignment_acceptor(auth_endpoint),
            Comment{
                "OMQ endpoint to talk to for authenticating new sessions",
                "ipc:///var/lib/session-router/auth.socket",
                "tcp://127.0.0.1:5555",
            });

        conf.define_option<std::string>(
            "network",
            "omq-auth-method",
            FullClientOnly,
            Default{"session-router.auth"},
            Comment{
                "OMQ function to call for authenticating new sessions",
                "session-router.auth",
            },
            [this](std::string arg) {
                if (arg.empty())
                    return;
                auth_method = std::move(arg);
            });

        conf.define_option<std::string>(
            "network",
            "auth-whitelist",
            FullClientOnly,
            MultiValue,
            Comment{
                "Manually add a remote endpoint by PUBKEY.{} address to the access whitelist."_format(CLIENT_TLD),
            },
            [this](std::string arg) {
                try
                {
                    auth_whitelist.insert(NetworkAddress{arg});
                }
                catch (const std::exception& e)
                {
                    throw std::invalid_argument{
                        "[network]:auth-whitelist: invalid .{} address '{}': {}"_format(CLIENT_TLD, arg, e.what())};
                }
            });

        conf.define_option<std::filesystem::path>(
            "network",
            "auth-file",
            FullClientOnly,
            MultiValue,
            Comment{
                "Read auth tokens from file to accept endpoint auth",
                "Can be provided multiple times",
            },
            [this, rel_base = conf.conf_dir](std::filesystem::path arg) {
                if (!arg.empty() && arg.is_relative())
                    arg = rel_base / arg;
                if (not exists(arg))
                    throw std::invalid_argument{"cannot load auth file {}: file does not exist"_format(arg)};
                auth_files.push_back(std::move(arg));
            });

        conf.define_option<std::string>(
            "network",
            "auth-file-type",
            FullClientOnly,
            Comment{
                "How to interpret the contents of an auth file.",
#ifdef SROUTER_HAVE_CRYPT
                "Possible values: hash, plaintext",
#else
                "Possible values: plaintext",
#endif
            },
            [this](std::string arg) {
                if (arg == "plain" || arg == "plaintext")
                    auth_file_type = auth::AuthFileType::PLAIN;
                else if (arg == "hashed" || arg == "hashes" || arg == "hash")
                {
#ifndef SROUTER_HAVE_CRYPT
                    throw std::invalid_argument{"Hashed auth files are not supported by this Session Router build"};
#endif
                    auth_file_type = auth::AuthFileType::HASHES;
                }
                else
                    throw std::invalid_argument{"Invalid auth file type '{}'"_format(arg)};
            });

        conf.define_option<std::string>(
            "network",
            "auth-static",
            FullClientOnly,
            MultiValue,
            Comment{
                "Manually add a static auth code to accept for endpoint auth",
                "Can be provided multiple times",
            },
            [this](std::string arg) { auth_static_tokens.emplace(std::move(arg)); });

        conf.define_option<bool>(
            "network",
            "reachable",
            FullClientOnly,
            Default{true},
            assignment_acceptor(is_reachable),
            Comment{
                "Determines whether we will pubish our service's ClientContact to the network (client default: TRUE)",
            });

        conf.define_option<bool>(
            "network",
            "auto-routing",
            FullClientOnly,
            Default{true},
            Comment{
                "Enable / disable automatic route configuration.",
                "When this is enabled and an exit is used Session Router will automatically configure the",
                "operating system routes to route public internet traffic through the exit node.",
                "This is enabled by default, but can be disabled if advanced/manual exit routing",
                "configuration is desired."},
            assignment_acceptor(enable_route_poker));

        conf.define_option<bool>(
            "network",
            "blackhole-routes",
            FullClientOnly,
            Default{true},
            Comment{
                "Enable / disable route configuration blackholes.",
                "When enabled Session Router will drop IPv4 and IPv6 traffic (when in exit mode) that is "
                "not",
                "handled in the exit configuration.  Enabled by default."},
            assignment_acceptor(blackhole_routes));

        conf.define_option<std::string>(
            "network",
            "ifname",
            NotEmbedded,
            Comment{
                "Interface name for Session Router traffic. If unset Session Router will look for a free name",
                "matching 'sr-tunN', starting at N=0 (e.g. sr-tun0, sr-tun1, ...) for clients; relays default",
                "to sr-tun@XXXXXXXX where XXXXXXXX is the first 8 hex digits of the Session node pubkey.",
#ifdef __linux__
                "",
                "On Linux, you can use '%d' in the name as a pattern to have the OS automatically choose",
                "a device name by replacing '%d' with a number to construct an unused interface name",
#endif
            },
            assignment_acceptor(_if_name));

        conf.define_option<std::string>(
            "network",
            "ifaddr",
            NotEmbedded,
            MultiValue,
            Comment{
                "Private IP and netmask to use to map Session Router traffic to local addresses.",
                "",
                "The IPs (one IPv4, one IPv6) given here will be the IPs that remote Session",
                "Router clients will access if attempting to establish connections to this",
                "Session Router instance, and the remainder of the IP range will be the addresses",
                "that this Session Router uses to send traffic to remote relay and client peers.",
                "That is, a remote client attempting to connect to you through Session Router",
                "will be tunneled to the IPv4 or IPv6 address specified here.",
                "",
                "For example, 172.16.0.1/16 will use 172.16.0.1 for this Session Router",
                "instance's IPv4 address and 172.16.x.y will be used to map connections to remote",
                "peer addresses.  For IPv6, fd2e:7365:7368::1/64 will use fd2e:7365:7368::1 for",
                "this Session Router instance, and will map other remotes to addresses in",
                "fd2e:7365:7368:0:w:x:y:z.  (These two ranges are the defaults if not specified",
                "*and* they are not already in use on the system).",
                "",
                "This option can be given twice: once to set an IPv4 address and range, and once",
                "to set an IPv6 address and range.  If one or the other is omitted then an unused",
                "private range (/16 for IPv4, and /64 for IPv6) will be automatically detected",
                "and used.",
                "",
                "An \"all-zero\" address can be used with a custom netmask to use auto-detection",
                "with a custom size: for instance \"0.0.0.0/10\" will auto-detect an unused /10",
                "IPv4 private address range, and \"::/56\" would look for an unused /56 IPv6",
                "address range.",
                "",
                "If you intend to run network daemons for others to connect to (for example",
                "HTTP), then it is recommended that you specify explicit IPv4 and IPv6 addresses",
                "here and set up network servers (such as nginx to serve HTTP traffic) to listen",
                "on those two addresses.  If you are only using Session Router to connect to",
                "remote instances then you can typically leave this blank to auto-select an",
                "unused network range.",
            },
            [this](std::string arg) {
                try
                {
                    auto ip_net = parse_ip_net(arg, 16, 64);

                    std::visit(
                        []<typename IPNet>(IPNet& in) {
                            if (in.ip != IPNet{}.ip && in.ip == in.to_range().ip)
                            {
                                if (auto next = in.ip.next_ip(); next and in.contains(*next))
                                {
                                    log::warning(
                                        logcat,
                                        "Invalid host IP '{}' in [network]:ifaddr (the network zero address is "
                                        "invalid); using '{}' instead",
                                        in.ip,
                                        *next);
                                    in.ip = std::move(*next);
                                }
                            }
                        },
                        ip_net);

                    if (auto* in4 = std::get_if<ipv4_net>(&ip_net))
                    {
                        if (_local_ip_net)
                            throw std::runtime_error{"cannot specify multiple IPv4 addresses"};
                        if (in4->ip == in4->broadcast())
                            throw std::runtime_error{"Cannot bind to the IPv4 network broadcast address"};
                        _local_ip_net = std::move(*in4);
                    }
                    else
                    {
                        if (_local_ipv6_net)
                            throw std::runtime_error{"cannot specify multiple IPv6 addresses"};
                        auto& n = std::get<ipv6_net>(ip_net);
                        if (n.mask > 64)
                            throw std::runtime_error{"local address IPv6 net mask must be /64 or smaller"};
                        _local_ipv6_net = std::move(n);
                    }
                }
                catch (const std::exception& e)
                {
                    throw std::invalid_argument{"[network]:ifaddr invalid value '{}': {}"_format(arg, e.what())};
                }
            });

        conf.define_option<std::string>(
            "network",
            "mapaddr",
            FullClientOnly,
            MultiValue,
            Comment{
                "Map a remote `.{}` or `.{}` address to always use a fixed local IPv4, IPv6, or both"_format(
                    CLIENT_TLD, RELAY_TLD),
                "(separated by a comma). For example:",
                "    mapaddr=kcpyawm9se7trdbzncimdi5t7st4p5mh9i1mg7gkpuubi4k4ku1y.{}:172.16.0.42,fd2e:7365:7368::42"_format(
                    RELAY_TLD),
                "    mapaddr=55fxrybf3jtausbnmxpgwcsz9t8qkf5pr8t5f4xyto4omjrkorpy.{}:fd2e:7365:7368::deca:f20"_format(
                    RELAY_TLD),
                "reserves the given IPv4/IPv6 address for the indicated pubkeys.",
                "",
                "Session Router addresses that are *not* explicitly mapped will use the next available unused IP",
                "(for IPv4), or a pubkey-derived address with fallback to next available address for IPv6.",
                "",
                "The given IP address(es) must be inside the ranges configured by ifaddr=, and ONS addresses",
                "cannot be used."},
            [this](std::string arg) {
                if (arg.empty())
                    return;

                const auto pos = arg.find(":");
                if (pos == std::string::npos)
                    throw std::invalid_argument{
                        "[network]:mapaddr invalid entry '{}': expected 'ADDR:IP' or 'ADDR:IP,IP'"_format(arg)};

                auto addr_arg = std::string_view{arg}.substr(0, pos);
                auto ips = split(std::string_view{arg}.substr(pos + 1), ",", true);
                if (ips.size() < 1 || ips.size() > 2)
                    throw std::invalid_argument{
                        "[network]:mapaddr invalid entry '{}': expected single IPv4, IPv6, or both with comma-separators"_format(
                            arg)};

                try
                {
                    NetworkAddress raddr{addr_arg};
                    for (const auto& ip : ips)
                    {
                        std::string ip_arg{ip};
                        bool inserted;
                        if (ip_arg.find(':') != std::string_view::npos)
                            inserted = _reserved_local_ipv6.emplace(raddr, ip_arg).second;
                        else
                            inserted = _reserved_local_ipv4.emplace(raddr, ip_arg).second;

                        if (!inserted)
                            throw std::invalid_argument{"Duplicate entry for pubkey"};
                    }
                }
                catch (const std::exception& e)
                {
                    throw std::invalid_argument{"[network]:mapaddr invalid entry '{}': {}"_format(arg, e.what())};
                }
            });

        conf.add_options_validator([this] {
            if (!_reserved_local_ipv4.empty())
            {
                if (ipv4_autoselect())
                    throw std::invalid_argument{"[network]:mapaddr requires an IPv4 range for [network]:ifaddr"};

                for (const auto& [netaddr, ip] : _reserved_local_ipv4)
                    if (!_local_ip_net->contains(ip))
                        throw std::invalid_argument{
                            "Invalid [network]:mapaddr mapping: {} is not within the configured IPv4 range {}"_format(
                                ip, *_local_ip_net)};
            }
            if (!_reserved_local_ipv6.empty())
            {
                if (ipv6_autoselect())
                    throw std::invalid_argument{"[network]:mapaddr requires an IPv6 range for [network]:ifaddr"};

                for (const auto& [netaddr, ip] : _reserved_local_ipv6)
                    if (!_local_ipv6_net->contains(ip))
                        throw std::invalid_argument{
                            "Invalid [network]:mapaddr mapping: {} is not within the configured IPv6 range {}"_format(
                                ip, *_local_ipv6_net)};
            }
        });

        conf.define_option<int>(
            "network",
            "expired-address-cache",
            NotEmbedded,
            Default{conf.type == config::Type::Relay ? 100 : 1000},
            Comment{
                "This controls how many recently expired connection addresses to remember: if a connection",
                "closed or expires then the assigned addresses are remembered in this cache and will be reserved",
                "and reused if the connection is reestablished while still in the cache.  This setting controls",
                "the maximum number of such addresses Session Router will remember.",
                "",
                "This cache does not persist across restarts: if you want a particular client to have a persistent",
                "address, use the mapaddr= setting instead.",
            });

        conf.define_option<std::string>(
            "network",
            "srv",
            FullClientOnly,
            MultiValue,
            Comment{
                "Specify SRV Records for services hosted on the SNApp for protocols that use SRV",
                "records for service discovery. Each line specifies a single SRV record as:",
                "    srv=_service._protocol priority weight port target.{}"_format(CLIENT_TLD),
                "and can be specified multiple times as needed.  If `target.sesh` is set to",
                "`localhost.sesh` it will be replaced with this Session Router's address.",
                "",
                "For more info see",
                "https://docs.oxen.io/products-built-on-oxen/session-router/snapps/hosting-snapps",
                "and general description of DNS SRV record configuration.",
            },
            [this](std::string arg) {
                auto maybe_srv = dns::SRVData::from_srv_string(arg);

                if (not maybe_srv)
                    throw std::invalid_argument{"Invalid SRV Record string: {}"_format(arg)};

                srv_records.push_back(std::move(*maybe_srv));
            });

#if 0
        conf.define_option<std::filesystem::path>(
            "network",
            "persist-addrmap-file",
            FullClientOnly,
            Comment{
                "If given this specifies a file in which to record mapped local tunnel addresses so",
                "the same local address will be used for the same Session Router address on reboot. If this",
                "is not specified then the local IP of remote Session Router targets will not persist across",
                "restarts of session_router.",
            },
            [this, rel_base = params.default_data_dir](std::filesystem::path file) {
                if (!file.empty() && file.is_relative())
                    file = rel_base / file;
                static constexpr auto addrmap_errorstr = "Invalid entry in persist-addrmap-file"sv;
                if (file.empty())
                    throw std::invalid_argument("persist-addrmap-file cannot be empty");

                if (not exists(file))
                    throw std::invalid_argument("persist-addrmap-file path invalid: {}"_format(file));

                bool load_file = true;
                {
                    constexpr auto ADDR_PERSIST_MODIFY_WINDOW = 1min;
                    const auto last_write_time = std::filesystem::last_write_time(file);
                    const auto now = decltype(last_write_time)::clock::now();

                    if (now < last_write_time or now - last_write_time > ADDR_PERSIST_MODIFY_WINDOW)
                    {
                        load_file = false;
                    }
                }

                std::string data;
                if (auto maybe = util::OpenFileStream<std::ifstream>(file, std::ios_base::binary); maybe and load_file)
                {
                    log::debug(logcat, "Config loading persisting address map file from path:{}", file);
                    maybe->seekg(0, std::ios_base::end);
                    const auto len = maybe->tellg();
                    maybe->seekg(0, std::ios_base::beg);
                    data.resize(len);
                    maybe->read(data.data(), len);
                }
                else
                {
                    auto err = "Config could not load persisting address map file from path:{}"_format(file);
                    log::warning(logcat, "{} {}", err, load_file ? "NOT FOUND" : "STALE");
                }

                if (not data.empty())
                {
                    log::trace(logcat, "Config parsing address map data: {}", srouter::buffer_printer{data});

                    const auto parsed = oxenc::bt_deserialize<oxenc::bt_dict>(data);

                    for (const auto& [key, value] : parsed)
                    {
                        try
                        {
                            quic::Address addr{key, 0};

                            std::variant<ipv4, ipv6> ip;

                            auto check_ip_okay = []<typename Range>(const std::optional<Range>& range, const auto& ip) {
                                if (range)
                                {
                                    bool bad = ip == range->ip || ip == range->to_range().ip;
                                    if constexpr (std::same_as<Range, ipv4_net>)
                                        bad = bad || ip == range->broadcast();
                                    if (bad)
                                    {
                                        log::warning(
                                            logcat, "{}: ignore invalid address map IP {}", addrmap_errorstr, ip);
                                        return false;
                                    }
                                    if (!range->contains(ip))
                                    {
                                        log::warning(
                                            logcat,
                                            "{}: IP {} is outside the configured local range {}",
                                            addrmap_errorstr,
                                            ip,
                                            range->to_range());
                                        return false;
                                    }
                                }
                                return true;
                            };

                            if (addr.is_ipv4())
                            {
                                if (!check_ip_okay(_local_ip_net, ip.emplace<ipv4>(addr.to_ipv4())))
                                    continue;
                            }
                            else
                            {
                                if (!check_ip_okay(_local_ipv6_net, ip.emplace<ipv6>(addr.to_ipv6())))
                                    continue;
                            }

                            const auto* arg = std::get_if<std::string>(&value);
                            if (not arg)
                            {
                                log::warning(logcat, "{}: {}", addrmap_errorstr, "not a string!");
                                continue;
                            }

                            if (is_valid_sns(*arg))
                            {
                                log::warning(logcat, "{}: {}", addrmap_errorstr, "cannot accept ONS names!");
                                continue;
                            }

                            try
                            {
                                NetworkAddress netaddr{*arg};
                                if (auto* ip4 = std::get_if<ipv4>(&ip))
                                    _reserved_local_ipv4.emplace(std::move(netaddr), std::move(*ip4));
                                else
                                    _reserved_local_ipv6.emplace(std::move(netaddr), std::move(std::get<ipv6>(ip)));
                            }
                            catch (const std::exception& e)
                            {
                                log::warning(logcat, "{}: invalid value {}: {}", addrmap_errorstr, *arg, e.what());
                                continue;
                            }
                        }
                        catch (const std::exception& e)
                        {
                            log::warning(
                                logcat,
                                "Exception caught parsing key:value (key:{}) pair in addr persist file:{}",
                                key,
                                e.what());
                        }
                    }
                }

                addr_map_persist_file = file;
            });
#endif
    }

    void DnsConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.add_section_comments(
            "dns",
            {
                "DNS configuration",
            });

        // Most non-linux platforms have loopback as 127.0.0.1/32, but linux uses 127.0.0.1/8 so
        // that we can bind to other 127.* IPs to avoid conflicting with something else that may be
        // listening on 127.0.0.1:53.
        constexpr std::array DefaultDNSBind{
#ifdef __linux__
#ifdef WITH_SYSTEMD
            // when we have systemd support add a random high port on loopback as well
            // see https://github.com/oxen-io/lokinet/issues/1887#issuecomment-1091897282
            Default{"127.0.0.1:0"},
#endif
            Default{"127.3.2.1"},
#else
            Default{"127.0.0.1"},
#endif
        };

        conf.define_option<std::string>(
            "dns",
            "listen",
            FullClientOnly,
            DefaultDNSBind,
            MultiValue,
            Comment{
                "Address(es) on which to listen for DNS requests.  This can either be an IP address",
                "(to use the default DNS port 53) or an IP followed by `:port' to listen on a custom",
                "port.  To specify an IPv6 address, surround the address with '[' and ']'.",
                "",
                "This option can be specified multiple times to bind to multiple addresses.",
                "",
                "If this Session Router instance has no need to establish outbound connection (for example,",
                "for a hidden service) then this can be set to an empty string to disable the DNS listener",
                "entirely.  WARNING: disabling this makes it impossible to make new outbound connections!",
            },
            [this](const std::string& arg) {
                if (not arg.empty())
                    _listen_addrs.push_back(quic::Address::parse(arg, DEFAULT_DNS_PORT));
            });

        conf.define_option<std::string>(
            "dns",
            "upstream",
            FullClientOnly,
            MultiValue,
            std::array{
                Default{"9.9.9.9"}, Default{"149.112.112.112"}, Default{"[2620:fe::fe]"}, Default{"[2620:fe::9]"}},
            Comment{
                "Upstream resolver(s) to use as fallback for non-Session Router addresses.",
                "Multiple values accepted.  Can be set to empty to disable upstream DNS resolution",
                "for advanced setups.",
                "",
                "If not specified, the default is to use Quad9 public DNS servers (https://quad9.net).",
            },
            [this](const std::string& arg) {
                if (not arg.empty())
                    _upstream_dns.push_back(quic::Address::parse(arg, DEFAULT_DNS_PORT));
            });

        conf.define_option<std::string>(
            "dns",
            "unbound",
            FullClientOnly,
            MultiValue,
            Comment{
                "This option can be used to supply custom options to libunbound, which is used",
                "internally when DNS requests are made that are not for a .sesh/.snode address.",
                "",
                "To add a custom option specify this option with a value of `unbound-option-name: value`;",
                "for example, to limit the maximum record cache time:",
                "    unbound=cache-max-ttl: 3600",
                "Or to enable DNSSEC validation:",
                "    unbound=trust-anchor-file: /path/to/dns/root.key",
                "",
                "You can use this option multiple times to specify more unbound options.",
                "",
                "See https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html",
                "for all supported unbound options.",
            },
            [this](std::string option) {
                auto pos = option.find(':');
                if (pos == std::string::npos)
                    throw std::invalid_argument{
                        "Invalid unbound option '{}': options must be formatted as `option: value`"_format(option)};
                auto key = std::string_view{option}.substr(0, pos);
                auto value = std::string_view{option}.substr(pos + 1);

                for (auto* s : {&key, &value})
                {
                    while (s->starts_with(' '))
                        s->remove_prefix(1);
                    while (s->ends_with(' '))
                        s->remove_suffix(1);
                }
                if (key.empty() || value.empty())
                    throw std::invalid_argument{
                        "Invalid unbound option '{}': key and/or value cannot be empty"_format(option)};

                unbound_opts.emplace_back("{}:"_format(key), std::string{value});
            });

        conf.define_option<std::string>(
            "dns",
            "unbound-hosts",
            FullClientOnly,
            Default{"SYSTEM"s},
            Comment{
                "Configures unbound to use the given `hosts' files when resolving addresses.  Can be",
                "used to add custom addresses or perform client-side DNS filtering.  If omitted or set",
                "to the string 'SYSTEM' then the system default (/etc/hosts, or WINDIR/etc/hosts on",
                "Windows) will be used.  Can be set to an empty string to not add any hosts file.",
            },
            [this, rel_base = conf.conf_dir](std::string p) {
                if (p.empty())
                    unbound_hosts.reset();
                else if (p == "SYSTEM")
                    unbound_hosts.emplace("SYSTEM");
                else
                {
                    std::filesystem::path path{p};
                    if (path.is_relative())
                        path = rel_base / path;
                    if (!exists(path))
                        throw std::invalid_argument{"[dns]:unbound-hosts file '{}' does not exist"_format(path)};
                    unbound_hosts = std::move(path);
                }
            });

        // Ignored option (used by the systemd service file to disable resolvconf configuration).
        conf.define_option<bool>(
            "dns",
            "no-resolvconf",
            FullClientOnly,
            Comment{
                "Can be uncommented and set to 1 to disable resolvconf configuration of Session Router "
                "DNS.",
                "(This is not used directly by Session Router itself, but by the Session Router init scripts",
                "on systems which use resolveconf)",
            });
    }

    void LinksConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.add_section_comments(
            "bind",
            {
                "This section allows specifying the IP that Session Router uses for incoming and outgoing",
                "connections.  For simple setups it can usually be left blank, but may be required",
                "for relays with multiple IP address, or relays that listen on a private IP with",
                "forwarded public traffic.",
            });

        auto parse_addr_for_link = [](std::string_view arg) {
            quic::Address a = quic::Address::parse(arg, 0);
            if (a.is_loopback())
                throw std::invalid_argument{"Invalid listen address: {} is a loopback address"_format(arg)};
            if (a.is_ipv6() && a.is_any_addr())
                a = quic::Address{ipv4{0, 0, 0, 0}, a.port()};
            else if (a.is_ipv6() && a.is_ipv4_mapped_ipv6())
                a.unmap_ipv4_from_ipv6();
            else if (a.is_ipv6())
                throw std::invalid_argument{"Invalid listen address: IPv6 addresses are not currently supported"};
            return a;
        };

        conf.define_option<std::string>(
            "bind",
            "listen",
            conf.type == config::Type::Relay
              ? Comment{
                "IP and/or port for Session Router to bind to for inbound/outbound connections.",
                "",
                "If IP is omitted then Session Router will search for a local network interface with a",
                "public IP address and use that IP (and will exit with an error if no such IP is found",
                "on the system).  If port is omitted then Session Router defaults to 1190.",
                "",
                "Examples:",
                "    listen=15.5.29.5:1099",
                "    listen=10.0.2.2",
                "    listen=:1234",
                "",
                "Note that a private range IP address (as in the second example above) requires also using",
                "[router]:public-ip/-port to specify the public IP address at which this router can be",
                "reached, and requires that traffic on that port is redirected to the listening internal",
                "address.",
                }
              : Comment{
                "IP and/or port for Session Router to use for connections to relays.",
                "",
                "Defaults to ':1091', which means to use port 1091 on any available address.",
                "",
                "Examples:",
                "    listen=15.5.29.5:1099 -- uses a specific IP and port",
                "    listen=10.0.2.2 -- uses a specific IP, default port (1191)",
                "    listen=:1234 -- uses any IP, port 1234",
            },
            [this, parse_addr_for_link](const std::string& arg) {
                if (listen_addr)
                    throw std::runtime_error{
                        "Multiple listen addresses found.  If upgrading from an older Session Router, delete extra "
                        "[bind]:inbound and [bind]:IP and use only one [bind]:listen"};
                listen_addr = parse_addr_for_link(arg);
            });
    }

    void ApiConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.add_section_comments(
            "api",
            {
                "JSON API settings",
            });

        constexpr std::array DefaultRPCBind{
            Default{"tcp://127.0.0.1:1190"},
#ifndef _WIN32
            Default{"ipc://rpc.sock"},
#endif
        };

        conf.define_option<bool>(
            "api",
            "enabled",
            NotEmbedded,
            Default{conf.type == config::Type::FullClient},
            assignment_acceptor(enable_rpc_server),
            Comment{
                "Determines whether or not the OMQ JSON API is enabled. By default this is enabled for clients, "
                "disabled for relays",
            });

        conf.define_option<std::string>(
            "api",
            "bind",
            NotEmbedded,
            DefaultRPCBind,
            MultiValue,
            [this, first = true](std::string arg) mutable {
                if (first)
                {
                    rpc_bind_addrs.clear();
                    first = false;
                }
                if (arg.find("://") == std::string::npos)
                {
                    arg = "tcp://" + arg;
                }
                rpc_bind_addrs.push_back(std::move(arg));
            },
            Comment{
                "IP addresses and ports to bind to.",
                "Recommend localhost-only for security purposes.",
            });

        // TODO: this was from pre-refactor:
        // TODO: add pubkey to whitelist
    }

    void OxendConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.add_section_comments(
            "oxend",
            {
                "Settings for communicating with oxend (when running as a Service Node relay)",
            });

        conf.define_option<bool>(
            "oxend",
            "disable-testing",
            Default{false},
            Hidden,
            RelayOnly,
            Comment{"Development option: set to true to disable reachability testing when using", "testnet"},
            assignment_acceptor(disable_testing));

        conf.define_option<std::string>(
            "oxend",
            "rpc",
            RelayOnly,
            Default{"ipc:///var/lib/oxen/oxend.sock"},
            Comment{
                "oxenmq control address for for communicating with oxend. Depends on oxend's",
                "lmq-local-control configuration option. By default this value should be",
                "ipc://OXEND-DATA-DIRECTORY/oxend.sock, such as:",
                "    rpc=ipc:///var/lib/oxen/oxend.sock",
                "    rpc=ipc:///home/USER/.oxen/oxend.sock",
                "but can use (non-default) TCP if oxend is configured that way:",
                "    rpc=tcp://127.0.0.1:5678",
            },
            [this](std::string arg) {
                // The full library installs a stricter oxenmq-based validator (see
                // config::install_full_config_validators); embedded/core-only builds fall back to a
                // cheap scheme check so we don't pull oxenmq into the core config library.
                if (config::oxend_rpc_addr_validator)
                    config::oxend_rpc_addr_validator(arg);
                else if (arg.find("://") == std::string::npos)
                    throw std::invalid_argument{
                        "Invalid [oxend]:rpc address '{}': expected a scheme such as ipc:// or tcp://"_format(arg)};
                rpc_addr = std::move(arg);
            });
    }

    void BootstrapConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.add_section_comments(
            "bootstrap",
            {
                "Configure nodes that will bootstrap us onto the network",
            });

        conf.define_option<std::string>(
            "bootstrap",
            "add-node",
            MultiValue,
            Comment{
                "Specify a bootstrap file containing a list of signed RelayContacts of service nodes",
                "which can act as a bootstrap. Can be specified multiple times. If set this overrides",
                "the built-in seed node list.",
            },
            [this](std::string arg) {
                if (arg.empty())
                    throw std::invalid_argument("cannot use empty filename as bootstrap");

                files.emplace_back(std::move(arg));

                if (not exists(files.back()))
                    throw std::invalid_argument{"file does not exist: {}"_format(files.back())};
            });
    }

    void LoggingConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.add_section_comments(
            "logging",
            {
                "Logging settings",
            });

        // quic logs a line per stream open and close at info, which is noise for a client that
        // tunnels TCP.  Embedded clients get nothing so that an embedding application's own
        // oxen::logging setup is left alone.
        const std::string default_log_levels = conf.type == config::Type::Relay ? "warn"
            : conf.type == config::Type::FullClient                             ? "*=info, quic=warn"
                                                                                : "";

        conf.define_option<std::string>(
            "logging",
            "type",
            Default{
                conf.type == config::Type::EmbeddedClient        ? "none"
                    : platform::is_android or platform::is_apple ? "system"
                                                                 : "print"},
            [this](std::string arg) {
                if (arg == "none")
                    type = std::nullopt;
                else
                    type = log::type_from_string(arg);
            },
            Comment{
                "Log type (format). Valid options are:",
                "  print - print logs to standard output",
                "  system - logs directed to the system logger (syslog/eventlog/etc.)",
                "  file - plaintext formatting to a file",
                (conf.type == config::Type::EmbeddedClient ? "  none - do not reset the logging system (for embedded "
                                                             "use with external oxen::logging)"
                                                           : ""),
            });

        conf.define_option<std::string>(
            "logging",
            "level",
            Default{default_log_levels},
            [this, defaults = default_log_levels](std::string arg) {
                // Category settings are cumulative, so appending is all that is needed: a setting
                // naming only categories ("tcp=debug") adjusts the defaults, while one naming a
                // global level ("debug") resets everything before it and so replaces them.
                levels = defaults.empty() || arg.empty() || arg == defaults ? std::move(arg) : defaults + ", " + arg;
            },
            Comment{
                "Minimum log severity level to print. Logging below this level will be ignored.",
                "Can also be set to a comma-separated list of individual categories, such as:",
                "    *=warn, logcat123=debug",
                "",
                "Setting only categories, without a global level, adjusts the defaults rather than",
                "replacing them, so e.g. 'tcp=debug' keeps the default level for everything else.",
                "",
                "Valid log levels, in ascending order, are:",
                "  trace, debug, info, warn, error, critical, off",
            });

        conf.define_option<std::string>(
            "logging",
            "file",
            Default{""},
            assignment_acceptor(file),
            Comment{
                "When using type=file this is the output filename.",
            });
    }

    void PathConfig::define_config_options(ConfigDefinition& conf)
    {
        conf.add_section_comments(
            "paths",
            {
                "Settings related to path selection such as number of hops and selection criteria",
            });

        conf.define_option<int>(
            "paths",
            "edge-connections",
            Default{CLIENT_ROUTER_CONNECTIONS},
            ClientOnly,
            Comment{
                "Minimum number of routers Session Router client will attempt to maintain direct (i.e. \"edge\")",
                "connections to.  All paths will start through one of these edges.",
                "",
                "Session Router may use more than this number of edges in single-hop connection mode",
                "(see [paths]:client-hops) and may use fewer connections if limited by [paths]:strict-edge."},
            lower_bounded_assignment_acceptor(edge_connections, 1, "[paths]:edge-connections"));

        conf.define_option<int>(
            "paths",
            "outbound-paths",
            ClientOnly,
            Default{2},
            Comment{
                "Number of paths to maintain per active outbound connection to a remote client or relay.",
                "Only one path is actively used at a time, but others are used for regular path rotation",
                "and as a fallback for path failure.",
                "",
                "Note that this value applies to EACH outbound connection separately: if you have active",
                "connections to 5 clients and 3 snodes, Session Router will maintain 16 outbound paths (at",
                "the default setting of 2).",
                "",
                "Setting this value to 1 is allowed, but will result in brief periods of packet loss",
                "whenever paths expire due to the lack of allowed backup path.",
            },
            bounded_assignment_acceptor(outbound_paths, 1, 4, "[paths]:outbound-paths"));

        conf.define_option<int>(
            "paths",
            "client-hops",
            ClientOnly,
            Default{3},
            Comment{
                "Number of hops to use when establishing a connection to a service node relay to",
                "communicate through that relay to another client.",
                "",
                "The overall number of hops to the remote client is this value PLUS the number of inbound",
                "hops the other client has configured for their inbound hops (via [paths]:inbound-hops).",
                "",
                "Setting this value to 1 puts Session Router into single-hop mode for the connection from this",
                "client to the aligned pivot router, which potentially weakens connection privacy as",
                "your public IP will be observable to any service node listed as a pivot for any remote",
                "client that you connect to."},
            bounded_assignment_acceptor(client_hops, 1, path::BUILD_LENGTH, "[paths]:client-hops"));

        conf.define_option<int>(
            "paths",
            "relay-hops",
            ClientOnly,
            Comment{
                "Number of hops to use when establishing a connection to talk to a service node.",
                "",
                "A value of 1 results in establishing direct connection to the snode (i.e. only",
                "encryption but no onion routing); 2 would select one intermediate snode to onion",
                "route through; 4 uses three intermediates, and so on, up to the maximum of 8.",
                "",
                "Additional hops increases privacy but also increase latency and reduces network",
                "performance through the path.",
                "",
                "If not set, this default to one greater than the value of [paths]:client-hops.",
                "",
                "Setting this value to 1 puts Session Router into single-hop mode for the connection from this",
                "client to service node (i.e. `.{}` addresses) which potentially weakens connection"_format(RELAY_TLD),
                "privacy as any service nodes you connect to will be able to observe your public IP."},
            bounded_assignment_acceptor(relay_hops_, 1, path::BUILD_LENGTH, "[paths]:relay-hops"));

        conf.define_option<int>(
            "paths",
            "inbound-paths",
            ClientOnly,
            Default{4},
            Comment{
                "Number of local paths that Session Router maintains for both network reachability (i.e. remote",
                "clients connecting to this instance) and network communication such as looking up",
                "client records and updating network state",
                "",
                "This value does NOT apply to paths that are built to reach external clients or relays.",
            },
            bounded_assignment_acceptor(inbound_paths, 1, 10, "[paths]:local-paths"));

        conf.define_option<int>(
            "paths",
            "inbound-paths-extra",
            FullClientOnly,
            Hidden,
            Default{0},
            Comment{
                "Extra inbound paths to use for Session Router connectivity.  This option is hidden as it is not",
                "meant for normal Session Router use, and may be removed or replaced without warning in the future",
            },
            lower_bounded_assignment_acceptor(inbound_paths_extra, 0, "[paths]:inbound-paths-extra"));

        conf.define_option<int>(
            "paths",
            "inbound-hops",
            ClientOnly,
            Comment{
                "Number of hops to use for inbound and general request connections (see [paths]:inbound-paths).",
                "",
                "When a remote Session Router is connecting to this instance, this controls the path length of the",
                "local side of the full client-to-client path (i.e. from the common relay \"pivot\" to this",
                "Session Router instance).",
                "",
                "If not set, this value defaults to the same value as [paths]:client-hops.",
            },
            bounded_assignment_acceptor(inbound_hops_, 1, path::BUILD_LENGTH, "[paths]:inbound-hops"));

        conf.define_option<int>(
            "paths",
            "inbound-pivot-reuse",
            ClientOnly,
            Default{1},
            Comment{
                "This configures the maximum number of times a single relay may be used as a path pivot.",
                "The default is one, meaning each inbound path is built to a distinct pivot, but special",
                "cases (such as a one-hop reachable endpoint using a small number of pivots) may want to",
                "increase this to allow multiple pivots to be used at once.  Leaving this at the default",
                "of 1 is recommended for most cases.",
            },
            lower_bounded_assignment_acceptor(inbound_pivot_reuse, 1, "[paths]:inbound-pivot-reuse"));

        conf.define_option<int>(
            "paths",
            "unique-range-size",
            Default{24},
            ClientOnly,
            [this](int arg) {
                if (arg > 32 or (arg < 4 and arg != 0))
                    throw std::invalid_argument{"[paths]:unique-range-size must be between 4 and 32, or 0"};

                unique_hop_netmask = static_cast<uint8_t>(arg);
            },
            Comment{
                "Netmask for router path selection; each router must be from a distinct IPv4 subnet",
                "of the given size.  Defaults to 24.",
                "",
                "For instance, setting this to 16 selects routers for each path that have distinct",
                "x.y.*.* IP addresses; 32 merely requires that each router have a unique IP.  Setting",
                "this to 0 disables IP uniqueness entirely (i.e. paths can be selected that go through",
                "different Session Router routers on the same IP)",
            });

        conf.define_option<std::chrono::seconds>(
            "paths",
            "acceptable-expiry",
            Default{300s},
            ClientOnly,
            Comment{
                "The minimum expiry time a path/pivot must have for it to be eligible when switching",
                "to a new path.  Inactive paths older than this will be replaced with new paths.",
            },
            bounded_assignment_acceptor(acceptable_expiry, 0s, path::MAX_LIFETIME / 2, "acceptable-expiry"));

        conf.define_option<std::chrono::seconds>(
            "paths",
            "min-expiry",
            Default{60s},
            ClientOnly,
            Comment{
                "The minimum allowed path/pivot expiry time (in seconds) of a currently active outbound path.",
                "When an active path reaches an expiry less than this value then the path to the remote will",
                "be rotated immediately to use a newer path.",
                "",
                "This value cannot be larger than acceptable-expiry.",
            },
            bounded_assignment_acceptor(min_expiry, 0s, path::MAX_LIFETIME / 2, "min-expiry"));

        conf.define_option<std::chrono::milliseconds>(
            "paths",
            "build-timeout",
            ClientOnly,
            Default{10s},
            Comment{
                "How long to wait for a session or path to establish before timing out the attempt.",
                "Value is in seconds, or milliseconds with an ms suffix (e.g. 2500ms).",
            },
            bounded_assignment_acceptor(build_timeout, 1ms, 1min, "[paths]:build-timeout"));

        conf.add_options_validator([this] {
            if (min_expiry > acceptable_expiry)
                throw std::invalid_argument{"[paths]:min-expiry cannot be longer than [paths]:acceptable-expiry"};
        });

        conf.define_option<std::chrono::seconds>(
            "paths",
            "ping-interval",
            Default{5s},
            ClientOnly,
            Comment{"How frequently to send pings along built paths to test that they are still alive."},
            lower_bounded_assignment_acceptor(ping_interval, 1s, "[paths]:ping-interval"));

        conf.define_option<int>(
            "paths",
            "max-missed-pings",
            Default{5},
            ClientOnly,
            Comment{
                "The maximum number of consecutive missed pings (see ping-interval) allowed for a path.  If a path",
                "misses more than this, the path will be considered to have died and be replaced."},
            lower_bounded_assignment_acceptor(max_missed_pings, 0, "[paths]:max-missed-pings"));

#ifdef SROUTER_DEBUG_PATH_SEED
        conf.define_option<uint64_t>(
            "paths", "debug-path-seed", ClientOnly, Hidden, assignment_acceptor(debug_path_seed));
#endif

        conf.define_option<std::string>(
            "paths",
            "strict-edge",
            ClientOnly,
            MultiValue,
            [this](std::string value) {
                RouterID router;
                if (value.size() == 64 && oxenc::is_hex(value))
                    oxenc::from_hex(value.begin(), value.end(), router.begin());
                else if (not router.from_relay_address(value))
                    throw std::invalid_argument{"[paths]:strict-edge: Invalid .{} pubkey: {}"_format(RELAY_TLD, value)};

                if (not strict_edges.insert(router).second)
                    throw std::invalid_argument{
                        "[paths]:strict-edge: Duplicate strict connect .{} value: {}"_format(RELAY_TLD, value)};
            },
            Comment{
                R"(List of service node public keys of "edge" nodes (also known as "first hops") that)",
                "Session Router will exclusively use when establishing paths through the network.  You can use",
                "this to always use closer (i.e. lower latency) first hops, or to limit which network",
                "nodes see connections from your IP address.",
                "",
                "Public keys can be provided either in native Session Router address format (ADDR.{}), or using"_format(
                    RELAY_TLD),
                "the 64-character hexademical pubkey notation common used for Session service nodes.",
                "Specify this option multiple times to specify multiple allowed edge nodes.",
                "",
                "Note that only registered service node pubkeys will be used, and so connectivity will be",
                "lost entirely if all of the listed pubkeys are or become deregistered.",
                "",
                "This option is incompatible with single-hop outbound path mode (see `[paths]:client-hops`",
                "and `[paths]:relay-hops`).",
                "",
                "Note that if bootstrapping is needed a connection will be made to the configured bootstrap",
                "nodes to obtain an initial router list.  See [bootstrap]:add-node if you want to also",
                "override the nodes used for bootstrapping."});

        conf.add_options_validator([this] {
            if (strict_edges.empty())
                return;
            if (client_hops == 1)
                throw std::invalid_argument{
                    "[paths]:strict-edge cannot be used with [paths]:client-hops=1 single hop mode"};
            if (relay_hops_ and *relay_hops_ == 1)
                throw std::invalid_argument{
                    "[paths]:strict-edge cannot be used with [paths]:relay-hops=1 single hop mode"};
        });

        conf.define_option<std::string>(
            "paths",
            "blacklist-snode",
            ClientOnly,
            MultiValue,
            Comment{
                "Adds a Session Router relay `.{}` address to the list of relays to avoid when"_format(RELAY_TLD),
                "connecting to edges or building paths. Can be specified multiple times.",
            },
            [this](std::string arg) {
                RouterID id;
                if (not id.from_relay_address(arg))
                    throw std::invalid_argument{"Invalid RouterID: {}"_format(arg)};

                auto itr = snode_blacklist.emplace(std::move(id));
                if (not itr.second)
                    throw std::invalid_argument{"Duplicate blacklist-snode: {}"_format(arg)};
            });

#ifdef WITH_GEOIP
        conf.defineOption<std::string>(
            "paths",
            "exclude-country",
            ClientOnly,
            MultiValue,
            [this](std::string arg) { m_ExcludeCountries.emplace(lowercase_ascii_string(std::move(arg))); },
            Comment{
                "Exclude a country given its 2 letter country code from being used in path builds.",
                "For example:",
                "    exclude-country=DE",
                "would avoid building paths through routers with IPs in Germany.",
                "This option can be specified multiple times to exclude multiple countries",
                "Note that this option does not affect the final relay or pivot in outgoing paths",
            });
#endif
    }

    Config::Config(config::Type type, std::filesystem::path conf_file)
        : Config{type, util::file_to_string(conf_file), conf_file.parent_path(), util::path_as_str(conf_file)}
    {}

    Config::Config(config::Type type, std::string ini, std::filesystem::path conf_dir, std::string config_for_debug)
        : type{type}, defs{type, std::move(conf_dir)}, parser{std::move(config_for_debug)}
    {
        for (ConfigBase* c : std::initializer_list<ConfigBase*>{
                 &router, &exit, &network, &paths, &dns, &links, &api, &oxend, &bootstrap, &logging})
            c->define_config_options(defs);

        parser.load_from_str(std::move(ini));

        parser.iter_all_sections([this](std::string_view section, const SectionValues& values) {
            for (const auto& [k, vs] : values)
                for (const auto& v : vs)
                    defs.add_config_value(section, k, v);
        });

        defs.process();
    }

}  // namespace srouter
