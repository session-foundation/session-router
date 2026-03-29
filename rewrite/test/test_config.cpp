#include <catch2/catch_test_macros.hpp>
#include <sr/node/config.hpp>

#include <filesystem>
#include <fstream>

using namespace sr::node;

static std::filesystem::path write_temp_config(const std::string& content)
{
    auto path = std::filesystem::temp_directory_path() / "sr_test_config.ini";
    std::ofstream f{path};
    f << content;
    return path;
}

TEST_CASE("Config defaults are sane", "[node][config]")
{
    Config cfg;
    REQUIRE(cfg.listen_port == 1090);
    REQUIRE(cfg.is_relay == false);
    REQUIRE(cfg.tun_name == "sr0");
    REQUIRE(cfg.target_paths == 6);
    REQUIRE(cfg.edge_connections == 4);
    REQUIRE(cfg.tick_interval == std::chrono::milliseconds{250});
}

TEST_CASE("Config from INI file", "[node][config]")
{
    auto path = write_temp_config(R"(
[router]
is-relay = true
data-dir = /tmp/sr-test

[network]
port = 2222

[tun]
name = test0
ip = 10.1.0.1
netmask = 24

[dns]
bind = 127.0.0.1:5353
upstream = 8.8.8.8

[paths]
hops = 4
target = 8

[bootstrap]
file = /tmp/bootstrap1.signed
file = /tmp/bootstrap2.signed
)");

    auto cfg = Config::from_file(path);
    REQUIRE(cfg.is_relay == true);
    REQUIRE(cfg.data_dir == "/tmp/sr-test");
    REQUIRE(cfg.listen_port == 2222);
    REQUIRE(cfg.tun_name == "test0");
    REQUIRE(cfg.tun_ip == "10.1.0.1");
    REQUIRE(cfg.tun_netmask == 24);
    REQUIRE(cfg.dns_bind == "127.0.0.1:5353");
    REQUIRE(cfg.dns_upstream == "8.8.8.8");
    REQUIRE(cfg.min_path_hops == 4);
    REQUIRE(cfg.target_paths == 8);
    REQUIRE(cfg.bootstrap_files.size() == 2);

    std::filesystem::remove(path);
}

TEST_CASE("Config from INI ignores comments and blanks", "[node][config]")
{
    auto path = write_temp_config(R"(
# This is a comment
; So is this

[network]
port = 3333

# Another comment
)");

    auto cfg = Config::from_file(path);
    REQUIRE(cfg.listen_port == 3333);
    std::filesystem::remove(path);
}

TEST_CASE("Config from_file throws on missing file", "[node][config]")
{
    REQUIRE_THROWS(Config::from_file("/nonexistent/path.ini"));
}

TEST_CASE("Config from_args with --relay", "[node][config]")
{
    const char* args[] = {"session-router", "--relay"};
    auto cfg = Config::from_args(2, const_cast<char**>(args));
    REQUIRE(cfg.is_relay == true);
}

TEST_CASE("Config from_args with --config", "[node][config]")
{
    auto path = write_temp_config("[network]\nport = 4444\n");
    std::string path_str = path.string();
    const char* args[] = {"session-router", "--config", path_str.c_str()};
    auto cfg = Config::from_args(3, const_cast<char**>(args));
    REQUIRE(cfg.listen_port == 4444);
    std::filesystem::remove(path);
}
