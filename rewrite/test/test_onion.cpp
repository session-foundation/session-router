#include <catch2/catch_test_macros.hpp>

#include <sr/path/onion.hpp>
#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/dh.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::path;
using namespace sr::contact;
using namespace sr::crypto;

static Ed25519KeyPair relay_keys[4];
static bool relay_keys_init[4] = {};
static RelayContact make_relay(size_t idx) {
    if (!relay_keys_init[idx]) {
        relay_keys[idx] = Ed25519KeyPair::generate();
        relay_keys_init[idx] = true;
    }
    auto& kp = relay_keys[idx];
    RouterID rid{kp.pk};
    RelayAddress addr{static_cast<uint32_t>(0x0100007F + idx), 1090};
    auto now = std::chrono::system_clock::now();
    RelayContact rc{rid, addr, {0, 10, 0}, now};
    rc.sign(kp.sk);
    return rc;
}

TEST_CASE("Onion build and decrypt 2-hop", "[path][onion]") {
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1}, ephemeral, std::chrono::seconds(1200));

    REQUIRE(result.hops.size() == 2);

    // Hop 0 (edge) decrypts its frame
    auto frame0 = std::span<const std::byte>(
        result.frames.data(), BUILD_FRAME_SIZE);
    auto df0 = decrypt_build_frame(frame0, relay_keys[0].sk, relay_keys[0].pk);
    REQUIRE(df0.has_value());
    REQUIRE(df0->rxid == result.hops[0].rxid);
    REQUIRE(df0->txid == result.hops[0].txid);
    REQUIRE(df0->lifetime == std::chrono::seconds(1200));
}

TEST_CASE("Onion frame count matches BUILD_LENGTH", "[path][onion]") {
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1}, ephemeral, std::chrono::seconds(1200));

    // Total message should be BUILD_LENGTH * BUILD_FRAME_SIZE
    REQUIRE(result.frames.size() == BUILD_MSG_SIZE);
}

TEST_CASE("Onion shared secrets are unique per hop", "[path][onion]") {
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto r2 = make_relay(2);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1, r2}, ephemeral, std::chrono::seconds(1200));

    REQUIRE(result.hops[0].shared_secret != result.hops[1].shared_secret);
    REQUIRE(result.hops[1].shared_secret != result.hops[2].shared_secret);
}

TEST_CASE("Onion xor_nonces derived correctly", "[path][onion]") {
    auto r0 = make_relay(0);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0}, ephemeral, std::chrono::seconds(600));

    auto expected_xn = sr::crypto::derive_xor_nonce(result.hops[0].shared_secret);
    REQUIRE(result.hops[0].xor_nonce == expected_xn);
}
