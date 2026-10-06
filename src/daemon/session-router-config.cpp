// Script that generates Session Router configuration files and keys

#include "config/config.hpp"
#include "constants/version.hpp"
#include "crypto/crypto.hpp"
#include "crypto/key_manager.hpp"
#include "util/file.hpp"
#include "util/formattable.hpp"
#include "util/logging.hpp"

#include <CLI/CLI.hpp>
#include <oxenmq/address.h>

#include <charconv>
#include <stdexcept>

#ifndef _WIN32
extern "C"
{
#include <sys/ioctl.h>
#include <unistd.h>
}
#endif

auto& logcat = srouter::log_global;

int main(int argc, char* argv[])
{
    using namespace srouter;

    log::add_sink(log::Type::Print, "stderr", "[\x1b[1m%n\x1b[0m:%^%l%$] %v");
    log::reset_level(log::Level::warn);
    log::set_level(logcat, log::Level::info);

    CLI::App cli{
        "Session Router is a free, open source, private, decentralized, market-based sybil resistant "
        "and IP-based onion routing network"};

    size_t wrap_width = 0;
#ifndef _WIN32
    if (struct winsize w{}; isatty(STDOUT_FILENO) && ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1)
        wrap_width = w.ws_col;
    else
#endif
        if (const char* cols = std::getenv("COLUMNS"))
    {
        size_t c;
        if (auto [ptr, ec] = std::from_chars(cols, cols + std::strlen(cols), c); ec == std::errc())
            wrap_width = c;
    }

    if (wrap_width < 80)
        wrap_width = 80;
    --wrap_width;  // So that we aren't putting a character in the very last position which makes
                   // some terminals add a blank line
    cli.get_formatter()->column_width(30);
    cli.get_formatter()->right_column_width(wrap_width - 30);
    cli.get_formatter()->description_paragraph_width(wrap_width);

    bool version = false;
    bool client = false;
    bool hidden_svc = false;
    bool embedded = false;
    bool relay = false;
    bool persist_key = false;
    bool gen_key = false;
    bool show_key = false;
    bool testnet = false;
    bool force = false;

    std::filesystem::path target;
    std::filesystem::path data_dir;

    std::string listen_addr;
    std::string public_ip;
    uint16_t public_port = 0;
    std::string oxend_rpc;

    // flags: boolean values in command_line_options struct
    cli.add_flag("--version", version, "Session Router version");

    auto mode = cli.add_option_group("mode", "Generation mode");
    mode->add_flag("-c,--client", client, "Generate a default full client configuration");
    mode->add_flag(
        "-H,--hidden-service",
        hidden_svc,
        "Generate a client configuration with preconfigured settings for running as a hidden service (persistent key, "
        "disable DNS, increased inbound paths)");
    mode->add_flag("-e,--embedded-config", embedded, "Generate a default config file for use with an embedded client");
    mode->add_flag("-r,--relay", relay, "Generate a relay config for use as a relay as part of a Session Node");
    mode->add_flag(
        "-k,--key",
        gen_key,
        "Generate just a key file (i.e. no config) that can be used as a persistent Session Router key");
    mode->add_flag(
        "-s,--show-key",
        show_key,
        "Read the given target as a key file and show its public key and address information");

    mode->require_option(1);

    cli.add_flag(
        "-f,--force",
        force,
        "Force writing the given output config or key file even if it already exists, overwriting the existing "
        "file(s).");

    cli.add_option(
        "-d,--data-dir",
        data_dir,
        "Specify an explicit data dir to use in the config file.  If not specified, data files will be stored in "
        "$HOME/.session-router");

    cli.add_option(
        "--listen",
        listen_addr,
        "Specifies an address and/or port on which to bind for the [bind]:listen directive, in the form "
        "'a.b.c.d:PORT', ':PORT', or 'a.b.c.d'");
    cli.add_flag("-t,--testnet", testnet, "Configure to use testnet instead of the main session-router network");

    auto client_opts = cli.add_option_group(
        "client",
        "Client-specific options; these only have effect when generating a client/hidden service/embedded config.");
    client_opts->add_flag(
        "-p,--persistent-key",
        persist_key,
        "Enable a persistent key file in the generated client or embedded config (this option is automatic for hidden "
        "service configs).  The key will have the same name as the generated config but with a '.key' extension.");

    auto relay_opts =
        cli.add_option_group("relay", "Relay-specific options; these only have effect when generating a relay config");
    relay_opts->add_option(
        "--public-ip",
        public_ip,
        "The public IPv4 address on which this session router relay is reachable (sets [router]:public-ip)");
    relay_opts->add_option(
        "--public-port",
        public_port,
        "The public IPv4 UDP port on which this session router relay is reachable (sets [router]:public-port)");
    relay_opts->add_option(
        "--oxend-rpc",
        oxend_rpc,
        "The oxend RPC socket used to communicate with this Session Node's oxend server ([oxend]:rpc); typically "
        "ipc:///PATH/TO/oxend.sock");

    cli.add_option(
           "filename",
           target,
           "Filename for the generated config or key file, typically ending with .ini (config generation) or .key (key "
           "generation).  If the given filename is inside a directory then this script will attempt to create the "
           "given directory if it does not already exist when generating the file.")
        ->required();

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    if (version)
    {
        std::cout << VERSION_FULL << std::endl;
        return 0;
    }

    auto make_parent_dir = [](const std::filesystem::path& target) {
        if (target.has_parent_path())
            std::filesystem::create_directories(target.parent_path());
    };

    auto check_overwrite = [&](const std::filesystem::path& target) {
        if (!force && exists(target))
            throw std::runtime_error{
                "File '{}' already exists and --force not given: refusing to overwrite it"_format(target)};
    };

    auto show_pubkey = [&](const Ed25519SecretKey& key, std::string_view prefix = ""sv) {
        fmt::print("{}Public key: {}\n", prefix, oxenc::to_hex(key.pubkey_span()));
        fmt::print("{}SR address: {}.{}\n", prefix, key.to_pubkey(), CLIENT_TLD);
    };

    try
    {
        if (show_key)
        {
            if (!std::filesystem::exists(target))
                throw std::runtime_error{"Key file ({}) does not exist"_format(target)};

            Ed25519SecretKey skey;
            KeyManager::load_from_file(skey, target);
            fmt::print("{} key info:\n\n", target);
            show_pubkey(skey);
            fmt::print("\n");
        }
        else if (gen_key)
        {
            auto secret_key = Ed25519SecretKey::generate();
            check_overwrite(target);
            KeyManager::write_to_file(secret_key, target);

            fmt::print("Saved keypair to {}.\n\n", target);
            show_pubkey(secret_key);
            fmt::print("\n");
        }
        else
        {
            if (!target.has_extension())
                target.replace_extension(".ini");

            check_overwrite(target);
            assert(client || hidden_svc || embedded || relay);
            std::string extra_ini = "";
            if (hidden_svc || (!relay && persist_key))
            {
                Ed25519SecretKey skey;
                auto key_file = target;
                key_file.replace_extension(".key");
                std::string_view action;
                if (exists(key_file))
                {
                    KeyManager::load_from_file(skey, key_file);
                    action = "Using existing"sv;
                }
                else
                {
                    skey = Ed25519SecretKey::generate();
                    KeyManager::write_to_file(skey, key_file);
                    action = "Generated persistent"sv;
                }

                log::info(
                    logcat,
                    "{} key file {} (with pubkey address: {}.{})",
                    action,
                    key_file,
                    skey.to_pubkey(),
                    CLIENT_TLD);

                extra_ini += "[network]\nkeyfile={}\n"_format(util::path_as_str(key_file.filename()));
            }

            if (hidden_svc)
            {
                extra_ini += "[paths]\ninbound-paths=8\n";
                extra_ini += "[dns]\nlisten=\n";
            }

            if (!listen_addr.empty())
            {
                try
                {
                    auto addr = oxen::quic::Address::parse(listen_addr, 0);
                    if (!addr.is_ipv4() && !addr.is_any_addr())
                        throw std::invalid_argument{"IPv4 address required"};
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error{"Invalid --listen address: {}"_format(e.what())};
                }
                extra_ini += "[bind]\nlisten={}\n"_format(listen_addr);
            }

            if (relay)
            {
                if (!public_ip.empty())
                {
                    quic::ipv4 addr;
                    try
                    {
                        addr = quic::ipv4{public_ip};
                        quic::Address a{addr};
                        if (!quic::Address{addr}.is_public_ip())
                            throw std::invalid_argument{"{} is not publicly addressable"_format(addr)};
                    }
                    catch (const std::exception& e)
                    {
                        throw std::runtime_error{"Invalid --public-ip IPv4 address: {}"_format(e.what())};
                    }
                    extra_ini += "[router]\npublic-ip={}\n"_format(addr);
                }
                if (public_port > 0)
                    extra_ini += "[router]\npublic-port={}\n"_format(public_port);
                if (!oxend_rpc.empty())
                {
                    try
                    {
                        (void)oxenmq::address{oxend_rpc};
                    }
                    catch (const std::exception& e)
                    {
                        throw std::runtime_error{"Invalid --oxend-rpc value: {}"_format(e.what())};
                    }
                    extra_ini += "[oxend]\nrpc={}\n"_format(oxend_rpc);
                }
            }

            if (!data_dir.empty())
                extra_ini += "[router]\ndata-dir={}\n"_format(util::path_as_str(data_dir));

            if (testnet)
                extra_ini += "[router]\nnetid=testnet\n";

            Config conf{
                relay          ? config::Type::Relay
                    : embedded ? config::Type::EmbeddedClient
                               : config::Type::FullClient,
                extra_ini};

            auto ini = conf.defs.generate_ini_config(true);
            util::buffer_to_file(target, ini);

            log::info(logcat, "Wrote config to {}", target);
        }
    }
    catch (const std::exception& e)
    {
        log::error(logcat, "Error: {}", e.what());
        return 2;
    }
    return 0;
}
