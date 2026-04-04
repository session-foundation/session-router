#include <catch2/catch_test_macros.hpp>
#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/dh.hpp>
#include <sr/crypto/types.hpp>
#include <sr/path/onion.hpp>

using namespace sr::path;
using namespace sr::contact;
using namespace sr::crypto;

static Ed25519KeyPair relay_keys[4];
static bool relay_keys_init[4] = {};
static RelayContact make_relay(size_t idx)
{
    if (!relay_keys_init[idx])
    {
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

TEST_CASE("Onion build and decrypt 2-hop", "[path][onion]")
{
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1}, ephemeral, std::chrono::seconds(1200));

    REQUIRE(result.hops.size() == 2);

    // Hop 0 (edge) decrypts its frame
    auto frame0 = std::span<const std::byte>(result.frames.data(), BUILD_FRAME_SIZE);
    auto df0 = decrypt_build_frame(frame0, relay_keys[0].sk, relay_keys[0].pk);
    REQUIRE(df0.has_value());
    REQUIRE(df0->rxid == result.hops[0].rxid);
    REQUIRE(df0->txid == result.hops[0].txid);
    REQUIRE(df0->lifetime == std::chrono::seconds(1200));
}

TEST_CASE("Onion frame count matches BUILD_LENGTH", "[path][onion]")
{
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1}, ephemeral, std::chrono::seconds(1200));

    // Total message should be BUILD_LENGTH * BUILD_FRAME_SIZE
    REQUIRE(result.frames.size() == BUILD_MSG_SIZE);
}

TEST_CASE("Onion shared secrets are unique per hop", "[path][onion]")
{
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto r2 = make_relay(2);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1, r2}, ephemeral, std::chrono::seconds(1200));

    REQUIRE(result.hops[0].shared_secret != result.hops[1].shared_secret);
    REQUIRE(result.hops[1].shared_secret != result.hops[2].shared_secret);
}

TEST_CASE("Onion xor_nonces derived correctly", "[path][onion]")
{
    auto r0 = make_relay(0);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0}, ephemeral, std::chrono::seconds(600));

    auto expected_xn = sr::crypto::derive_xor_nonce(result.hops[0].shared_secret);
    REQUIRE(result.hops[0].xor_nonce == expected_xn);
}

TEST_CASE("Onion hop ID chaining: hop[N].rxid == hop[N-1].txid", "[path][onion]")
{
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto r2 = make_relay(2);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1, r2}, ephemeral, std::chrono::seconds(1200));

    // Hop 1's rxid = Hop 0's txid
    REQUIRE(result.hops[1].rxid == result.hops[0].txid);
    // Hop 2's rxid = Hop 1's txid
    REQUIRE(result.hops[2].rxid == result.hops[1].txid);
}

TEST_CASE("Onion hop ID chaining: pivot txid == pivot rxid", "[path][onion]")
{
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1}, ephemeral, std::chrono::seconds(1200));

    // Pivot is the last hop: txid == rxid
    auto& pivot = result.hops.back();
    REQUIRE(pivot.txid == pivot.rxid);
}

TEST_CASE("Path message framing: append and strip trailer", "[path][framing]")
{
    std::vector<std::byte> payload(100);
    randombytes_buf(payload.data(), payload.size());

    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());
    HopID hopid = random_hop_id();

    auto msg = append_path_trailer(payload, nonce, hopid, PATH_MSG_DATA_OR_CONTROL);
    REQUIRE(msg.size() == payload.size() + PATH_TRAILER_SIZE);

    std::span<std::byte> payload_out;
    auto trailer = strip_path_trailer(msg, payload_out);
    REQUIRE(trailer.has_value());
    REQUIRE(trailer->nonce == nonce);
    REQUIRE(trailer->hopid == hopid);
    REQUIRE(trailer->msgtype == PATH_MSG_DATA_OR_CONTROL);
    REQUIRE(payload_out.size() == payload.size());
    REQUIRE(std::equal(payload_out.begin(), payload_out.end(), payload.begin()));
}

TEST_CASE("Path message framing: session handshake type", "[path][framing]")
{
    std::vector<std::byte> payload = {std::byte{0x42}};
    Nonce nonce{};
    HopID hopid{};

    auto msg = append_path_trailer(payload, nonce, hopid, PATH_MSG_SESSION_HANDSHAKE);
    std::span<std::byte> payload_out;
    auto trailer = strip_path_trailer(msg, payload_out);
    REQUIRE(trailer.has_value());
    REQUIRE(trailer->msgtype == PATH_MSG_SESSION_HANDSHAKE);
}

TEST_CASE("Path message framing: too short returns nullopt", "[path][framing]")
{
    std::vector<std::byte> short_msg(PATH_TRAILER_SIZE - 1);
    std::span<std::byte> payload_out;
    auto trailer = strip_path_trailer(short_msg, payload_out);
    REQUIRE_FALSE(trailer.has_value());
}

TEST_CASE("Onion only encrypts real frames, not dummies", "[path][onion]")
{
    auto r0 = make_relay(0);
    auto r1 = make_relay(1);
    auto ephemeral = Ed25519KeyPair::generate();

    auto result = build_onion({r0, r1}, ephemeral, std::chrono::seconds(1200));

    // 2 real hops, 6 dummy frames
    // Dummy frames (index 2-7) should still be random data (not all zeros)
    bool has_nonzero = false;
    for (size_t i = 2 * BUILD_FRAME_SIZE; i < BUILD_MSG_SIZE; ++i)
    {
        if (result.frames[i] != std::byte{0})
        {
            has_nonzero = true;
            break;
        }
    }
    REQUIRE(has_nonzero);
}
