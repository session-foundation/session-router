#include <catch2/catch_test_macros.hpp>

#include <sr/crypto/bt.hpp>
#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/types.hpp>

#include <arpa/inet.h>

using namespace sr::contact;
using namespace sr::crypto;

TEST_CASE("BT encode/decode basic dict", "[bt]") {
    std::string buf;
    {
        oxenc::bt_dict_producer dp{};
        dp.append("hello", "world");
        dp.append("num", 42);
        buf = std::move(dp).str();
    }

    oxenc::bt_dict_consumer dc{buf};
    REQUIRE(dc.key() == "hello");
    REQUIRE(dc.consume_string() == "world");
    REQUIRE(dc.key() == "num");
    REQUIRE(dc.consume_integer<int>() == 42);
}

TEST_CASE("RelayContact BT round-trip", "[bt][contact]") {
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};
    RelayAddress addr{htonl(0x7F000001), 1090};  // 127.0.0.1:1090
    auto now = std::chrono::system_clock::now();
    // Truncate to seconds for round-trip accuracy
    auto now_s = std::chrono::time_point_cast<std::chrono::seconds>(now);

    RelayContact rc{rid, addr, {0, 10, 0}, now_s};
    rc.sign(kp.sk);

    auto bt_data = rc.to_bt_unsigned();
    REQUIRE(bt_data.size() > 0);

    // Manually append signature for full BT
    // (to_bt_unsigned doesn't include sig, from_bt reads it optionally)

    // Parse back
    auto parsed = RelayContact::from_bt(bt_data);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->router_id() == rid);
    REQUIRE(parsed->address().port == 1090);
    REQUIRE(parsed->version() == std::array<uint8_t, 3>{0, 10, 0});
    REQUIRE(parsed->timestamp() == now_s);
}

TEST_CASE("RelayContact from_bt with invalid data returns nullopt", "[bt][contact]") {
    std::vector<std::byte> garbage(10);
    randombytes_buf(garbage.data(), garbage.size());

    auto parsed = RelayContact::from_bt(garbage);
    REQUIRE_FALSE(parsed.has_value());
}

TEST_CASE("RelayContact from_bt with empty data returns nullopt", "[bt][contact]") {
    auto parsed = RelayContact::from_bt({});
    REQUIRE_FALSE(parsed.has_value());
}

TEST_CASE("BT to_bytes and to_sv round-trip", "[bt]") {
    std::string original = "d5:helloi42ee";
    auto bytes = sr::bt::to_bytes(original);
    auto sv = sr::bt::to_sv(bytes);
    REQUIRE(sv == original);
}
