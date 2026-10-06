#pragma once

#include "address/address.hpp"
#include "address/ip_range.hpp"
#include "auth/auth.hpp"
#include "auth/file.hpp"
#include "constants/files.hpp"
#include "constants/path.hpp"
#include "contact/relay_contact.hpp"
#include "definition.hpp"
#include "dns/srv_data.hpp"
#include "ini.hpp"
#include "net/platform.hpp"
#include "net/policy.hpp"
#include "util/logging.hpp"
#include "util/str.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace srouter::config
{
    // Optional stricter validator for the [oxend]:rpc address, installed by the full library (which
    // parses it via oxenmq::address).  Null in embedded/core-only builds, where config.cpp falls
    // back to a cheap scheme check so oxenmq stays out of the core config library.  Installed via
    // install_full_config_validators().
    inline void (*oxend_rpc_addr_validator)(const std::string&) = nullptr;

    // Installs the full library's stricter config validators over the core defaults.  Defined in the
    // full (rpc) library; invoked by srouter::full::initialize().
    void install_full_config_validators();

}  // namespace srouter::config

namespace srouter
{
    using SectionValues = srouter::ConfigParser::SectionValues;
    using ConfigMap = srouter::ConfigParser::ConfigMap;

    inline constexpr uint16_t DEFAULT_CLIENT_PORT{1191};
    inline constexpr uint16_t DEFAULT_RELAY_PORT{1190};
    inline const quic::Address DEFAULT_CLIENT_ADDR{"0.0.0.0", DEFAULT_CLIENT_PORT};
    inline constexpr uint16_t DEFAULT_DNS_PORT{53};
    inline constexpr int CLIENT_ROUTER_CONNECTIONS{4};

    struct ConfigBase
    {
        virtual void define_config_options(ConfigDefinition& conf) = 0;
    };

    struct RouterConfig : ConfigBase
    {
        NetID net_id = NetID::MAINNET;

        std::filesystem::path data_dir;

        bool block_bogons = false;

        bool is_relay = false;

        std::optional<quic::Address> public_addr;

        void define_config_options(ConfigDefinition& conf) override;
    };

    /// config for path hop selection
    struct PathConfig : ConfigBase
    {
        int edge_connections{CLIENT_ROUTER_CONNECTIONS};

        // If non-empty then *only* use these nodes for first hops.  (Except for single-hop outbound
        // paths, which ignore this).
        std::unordered_set<RouterID> strict_edges;

        // Blacklist of relays to avoid using for edges or path hops
        std::unordered_set<RouterID> snode_blacklist;

        /// Number of paths to maintain for inbound reachability and network queries (such as
        /// looking up client contacts).
        int inbound_paths = 4;
        int inbound_paths_extra = 0;

        /// Number of times the same relay can be used as an inbound path pivot.  The default is 1,
        /// which means every inbound path uses a distinct relay.
        int inbound_pivot_reuse = 1;

        /// Length of the "inbound" paths we use for inbound connections and network queries.
        /// If unset, use client_hops.
        std::optional<int> inbound_hops_;

        // Retrieves the above, with built-in fallback to the client_hops value if not set.
        int inbound_hops() const { return inbound_hops_.value_or(client_hops); }

        /// Number of paths to maintain to *each* outgoing remote (relay or snode).
        int outbound_paths = 2;

        /// Number of hops when establishing a session to a relay (i.e. to a .snode, not *through* a
        /// relay to reach a client).
        std::optional<int> relay_hops_;

        /// Retrieves the working value for relay-hops: the value if explicitly set, else one more
        /// than the configured client hops.
        int relay_hops() const { return relay_hops_.value_or(std::min(client_hops + 1, path::BUILD_LENGTH)); }

        /// Number of hops when building an aligned path to a relay to reach a client on the other
        /// side.
        int client_hops = 3;

        /// in our hops what netmask will we use for unique ips for hops
        /// i.e. 32 for every hop unique ip, 24 unique /24 per hop, etc
        uint8_t unique_hop_netmask{0};

        // TODO: some day, if we ever support routers using public IPv6 addresses, there would need
        // to be a different ipv6 netmask value.

        std::chrono::seconds min_expiry = 1min;
        std::chrono::seconds acceptable_expiry = 5min;

        std::chrono::milliseconds build_timeout{10s};
        std::chrono::seconds ping_interval{5s};
        int max_missed_pings{5};

        // DEBUG ONLY: if set, this uses a repeatable RNG with the given seed for reproducible path
        // selection.  This option only has an effect if Session Router is configured with
        // -DSROUTER_DEBUG_PATH_SEED=ON (which is disabled by default).
        std::optional<uint64_t> debug_path_seed;

        void define_config_options(ConfigDefinition& conf) override;
    };

    /** TODO:
        - finalize supervenience of ExitConfig over deprecated config entries
     */

    /// Config options related to exit node services
    struct ExitConfig : ConfigBase
    {
        bool exit_enabled{false};

        // Used by RemoteHandler to provide auth tokens for remote exits
        //
        // The actual config puts everything in `sns_auth_tokens`, but then in config
        // post-processing we extract all the ones that are full pubkeys into `auth_tokens` and
        // leave the ones that need an sns lookup in `sns_auth_tokens`.
        std::unordered_map<NetworkAddress, std::string> auth_tokens;
        std::unordered_map<std::string, std::string> sns_auth_tokens;

        net::ExitPolicy exit_policy;

        // Remote client ONS exit addresses mapped to local IP ranges pending ONS address resolution
        // Reserved local IP ranges mapped to remote client ONS addresses (pending ONS resolution)
        std::unordered_map<std::string, std::vector<std::variant<ipv4_range, ipv6_range>>> sns_ranges;

        // Reserved local IP ranges mapped to remote client exit addresses
        std::unordered_map<NetworkAddress, std::vector<std::variant<ipv4_range, ipv6_range>>> ranges;

        void define_config_options(ConfigDefinition& conf) override;
    };

    struct NetworkConfig : ConfigBase
    {
        bool enable_profiling{false};
        bool save_profiles{false};

        std::optional<std::filesystem::path> keyfile;

        bool is_reachable{false};

        /*   Auth specific config   */
        auth::AuthType auth_type = auth::AuthType::NONE;
        auth::AuthFileType auth_file_type = auth::AuthFileType::HASHES;

        std::optional<std::string> auth_endpoint;
        std::optional<std::string> auth_method;

        std::unordered_set<NetworkAddress> auth_whitelist;

        std::unordered_set<std::string> auth_static_tokens;

        std::vector<std::filesystem::path> auth_files;

        std::vector<srouter::dns::SRVData> srv_records;

        // Contents of this file are read directly into ::_reserved_local_addrs
        // TODO.  Perhaps this should be in a sqlite db, though?
        // std::optional<std::filesystem::path> addr_map_persist_file;

        int expired_address_cache = 100;

        std::optional<std::string> _if_name;

        // [network]:ifaddr:
        std::optional<ipv4_net> _local_ip_net;
        std::optional<ipv6_net> _local_ipv6_net;

        bool ipv4_autoselect() const { return !_local_ip_net || !_local_ip_net->ip.addr; }
        bool ipv6_autoselect() const { return !_local_ipv6_net || !(_local_ipv6_net->ip.hi || _local_ipv6_net->ip.lo); }

        // Remote exit or hidden service addresses mapped to fixed local IP addresses
        // TODO:
        //  - load directly into TunEndpoint mapping
        //      - when a session is created, check mapping when assigning IP's
        std::unordered_map<NetworkAddress, ipv4> _reserved_local_ipv4;
        std::unordered_map<NetworkAddress, ipv6> _reserved_local_ipv6;

        // Used by RemoteHandler to provide auth tokens for remote exits
        std::unordered_map<NetworkAddress, std::string> exit_auths;
        std::unordered_map<std::string, std::string> sns_exit_auths;
        std::optional<net::ExitPolicy> traffic_policy;

        // FIXME: move into ExitConfig!
        bool enable_route_poker{false};
        bool blackhole_routes{false};

        void define_config_options(ConfigDefinition& conf) override;
    };

    struct DnsConfig : ConfigBase
    {
        std::vector<quic::Address> _upstream_dns;
        std::vector<quic::Address> _listen_addrs;

        // {"name:", "value"} pairs that we pass through to unbound to configure upstream DNS
        // requests:
        std::vector<std::pair<std::string, std::string>> unbound_opts;

        // Unbound config doesn't support specifying a hosts file for some reason but has to be done
        // via a different call.  We allow a magic "SYSTEM" value here to instruct unbound to use
        // the system default (by passing nullptr).
        std::optional<std::filesystem::path> unbound_hosts;

        void define_config_options(ConfigDefinition& conf) override;
    };

    struct LinksConfig : ConfigBase
    {
        std::optional<quic::Address> listen_addr;
        // nullopt means no cap.
        std::optional<size_t> max_udp_payload;

        void define_config_options(ConfigDefinition& conf) override;
    };

    struct ApiConfig : ConfigBase
    {
        bool enable_rpc_server = false;
        std::vector<std::string> rpc_bind_addrs;

        void define_config_options(ConfigDefinition& conf) override;
    };

    struct OxendConfig : ConfigBase
    {
        std::string rpc_addr;
        bool disable_testing = false;

        void define_config_options(ConfigDefinition& conf) override;
    };

    struct BootstrapConfig : ConfigBase
    {
        std::vector<std::filesystem::path> files;

        void define_config_options(ConfigDefinition& conf) override;
    };

    struct LoggingConfig : ConfigBase
    {
        // Log type.  If nullopt then Session Router will not set up logging sinks at all (this is
        // primarily aimed at embedded clients that have already set up logging).
        std::optional<log::Type> type = log::Type::Print;

        // levels can either be just a level ("warn"), or a list of cat levels such as:
        // "*=warning, cat1=debug, cat2*=trace".  See oxen-logging for more details.  If empty then
        // logging levels will not be set at all (and, again, is most useful for embedded clients).
        std::string levels;

        std::string file;

        void define_config_options(ConfigDefinition& conf) override;
    };

    struct Config
    {
        // Creates a config for the given Session Router instance type (relay, full client, or embedded
        // client), loading configuration data from the given string, if non-empty (all default config
        // otherwise).
        //
        // The config_dir argument (defaulting to cwd) has two effects:
        // - any relative paths for config options taking a path will resolve relative to it
        // - it is used as the default data directory if not explicit data directory is set in the
        //   config file.
        explicit Config(
            config::Type type,
            std::string config = "",
            std::filesystem::path config_dir = std::filesystem::current_path(),
            std::string config_for_debug = "config-string");

        // Creates a config for the given Session Router instance type (relay, full client, or embedded
        // client), loading configuration data from an existing file.
        //
        // Relative paths in the config will be relative to the directory containing the config
        // file.  The data directory, if not specified in the config file, will also default to that
        // directory.
        Config(config::Type type, std::filesystem::path config_file);

        Config(Config&&) = default;

        virtual ~Config() = default;

        const config::Type type;

        RouterConfig router;
        ExitConfig exit;
        NetworkConfig network;
        PathConfig paths;
        DnsConfig dns;
        LinksConfig links;
        ApiConfig api;
        OxendConfig oxend;
        BootstrapConfig bootstrap;
        LoggingConfig logging;

        // The config definitions for this config object that defines how config file options become
        // config settings.  This internally references all of the above config structs.
        ConfigDefinition defs;

      private:
        void load_config_data(std::string ini, std::optional<std::filesystem::path> fname = std::nullopt);

        ConfigParser parser;
    };

}  // namespace srouter
