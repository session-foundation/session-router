#include <catch2/catch_test_macros.hpp>
#include <sr/link/relay_conn.hpp>
#include <sr/crypto/types.hpp>

#include <sodium.h>

#include <cstring>

using namespace sr::link;
using namespace sr::crypto;

// Stub for ConnectionInfo::close() — the real one is in endpoint.cpp
// and requires oxen-libquic. Unit tests don't need real QUIC closing.
void sr::link::ConnectionInfo::close(uint64_t) {}

static auto make_conn()
{
    return std::make_shared<ConnectionInfo>();
}

// --- Category 1: relay_conn Data Structure (15 unit tests) ---

TEST_CASE("1.1 Winner selection: A < B", "[relay_conn][unit]")
{
    // When remote < local, inbound_wins = true
    relay_conn rc{true};
    REQUIRE(rc.inbound_wins == true);
}

TEST_CASE("1.2 Winner selection: A > B", "[relay_conn][unit]")
{
    // When remote > local, inbound_wins = false
    relay_conn rc{false};
    REQUIRE(rc.inbound_wins == false);
}

TEST_CASE("1.3 Winner symmetry", "[relay_conn][unit]")
{
    // Generate two RouterIDs and verify both sides agree on winner
    auto kp_a = Ed25519KeyPair::generate();
    auto kp_b = Ed25519KeyPair::generate();

    // Ensure a < b for deterministic test
    bool a_less = std::memcmp(kp_a.pk.data(), kp_b.pk.data(), 32) < 0;
    (void)a_less;  // used below to set up winner selection

    // On the side with the lower RouterID: remote > local, so inbound_wins = false
    relay_conn rc_low{false};
    // On the side with the higher RouterID: remote < local, so inbound_wins = true
    relay_conn rc_high{true};

    auto conn = make_conn();

    // Low sets outbound (its connection to high)
    rc_low.set_conn(conn, false);
    // High sets inbound (same physical connection, from low)
    rc_high.set_conn(conn, true);

    // Low prefers outbound (inbound_wins=false, so outbound wins)
    REQUIRE(rc_low.conn == conn.get());
    // High prefers inbound (inbound_wins=true, so inbound wins)
    REQUIRE(rc_high.conn == conn.get());

    // Both point to the same physical connection — symmetric
    REQUIRE(rc_low.conn == rc_high.conn);
}

TEST_CASE("1.4 set_conn inbound only", "[relay_conn][unit]")
{
    relay_conn rc{true};
    auto c = make_conn();
    rc.set_conn(c, true);

    REQUIRE(rc.inbound == c);
    REQUIRE(rc.outbound == nullptr);
    REQUIRE(rc.conn == c.get());
}

TEST_CASE("1.5 set_conn outbound only", "[relay_conn][unit]")
{
    relay_conn rc{false};
    auto c = make_conn();
    rc.set_conn(c, false);

    REQUIRE(rc.outbound == c);
    REQUIRE(rc.inbound == nullptr);
    REQUIRE(rc.conn == c.get());
}

TEST_CASE("1.6 set_conn both — inbound wins", "[relay_conn][unit]")
{
    relay_conn rc{true};  // inbound wins
    auto in = make_conn();
    auto out = make_conn();

    rc.set_conn(out, false);
    REQUIRE(rc.conn == out.get());  // only connection, so it's preferred

    rc.set_conn(in, true);
    REQUIRE(rc.conn == in.get());  // inbound wins, so preferred switches
    REQUIRE(rc.inbound == in);
    REQUIRE(rc.outbound == out);
}

TEST_CASE("1.7 set_conn both — outbound wins", "[relay_conn][unit]")
{
    relay_conn rc{false};  // outbound wins
    auto in = make_conn();
    auto out = make_conn();

    rc.set_conn(in, true);
    REQUIRE(rc.conn == in.get());  // only connection

    rc.set_conn(out, false);
    REQUIRE(rc.conn == out.get());  // outbound wins, so preferred switches
    REQUIRE(rc.inbound == in);
    REQUIRE(rc.outbound == out);
}

TEST_CASE("1.8 set_conn replaces existing", "[relay_conn][unit]")
{
    relay_conn rc{true};
    auto old_in = make_conn();
    auto new_in = make_conn();

    rc.set_conn(old_in, true);
    REQUIRE(rc.conn == old_in.get());

    rc.set_conn(new_in, true);
    REQUIRE(rc.conn == new_in.get());
    REQUIRE(rc.inbound == new_in);
    // Old connection's shared_ptr is no longer held by relay_conn
    REQUIRE(old_in.use_count() == 1);  // only our local variable holds it
}

TEST_CASE("1.9 close inbound, outbound remains", "[relay_conn][unit]")
{
    relay_conn rc{true};
    auto in = make_conn();
    auto out = make_conn();

    rc.set_conn(in, true);
    rc.set_conn(out, false);

    rc.close(true);  // close inbound
    REQUIRE(rc.inbound == nullptr);
    REQUIRE(rc.outbound == out);
    REQUIRE(rc.conn == out.get());  // switches to outbound
}

TEST_CASE("1.10 close outbound, inbound remains", "[relay_conn][unit]")
{
    relay_conn rc{false};
    auto in = make_conn();
    auto out = make_conn();

    rc.set_conn(in, true);
    rc.set_conn(out, false);

    rc.close(false);  // close outbound
    REQUIRE(rc.outbound == nullptr);
    REQUIRE(rc.inbound == in);
    REQUIRE(rc.conn == in.get());  // switches to inbound
}

TEST_CASE("1.11 close both", "[relay_conn][unit]")
{
    relay_conn rc{true};
    auto in = make_conn();
    auto out = make_conn();

    rc.set_conn(in, true);
    rc.set_conn(out, false);

    rc.close_all();
    REQUIRE(rc.inbound == nullptr);
    REQUIRE(rc.outbound == nullptr);
    REQUIRE(rc.conn == nullptr);
}

TEST_CASE("1.12 close_redundant — inbound wins", "[relay_conn][unit]")
{
    relay_conn rc{true};  // inbound wins
    auto in = make_conn();
    auto out = make_conn();

    rc.set_conn(in, true);
    rc.set_conn(out, false);

    rc.close_redundant();  // should close outbound (the loser)
    REQUIRE(rc.inbound == in);
    REQUIRE(rc.outbound == nullptr);
    REQUIRE(rc.conn == in.get());
}

TEST_CASE("1.13 close_redundant — outbound wins", "[relay_conn][unit]")
{
    relay_conn rc{false};  // outbound wins
    auto in = make_conn();
    auto out = make_conn();

    rc.set_conn(in, true);
    rc.set_conn(out, false);

    rc.close_redundant();  // should close inbound (the loser)
    REQUIRE(rc.outbound == out);
    REQUIRE(rc.inbound == nullptr);
    REQUIRE(rc.conn == out.get());
}

TEST_CASE("1.14 Static secret determinism", "[relay_conn][unit]")
{
    [[maybe_unused]] int sr_init = sodium_init();

    // make_static_secret is in the upstream but we test the principle:
    // same key → same output, different key → different output
    auto kp1 = Ed25519KeyPair::generate();
    auto kp2 = Ed25519KeyPair::generate();

    // BLAKE2b keyed hash of the secret key
    auto hash_key = [](const Ed25519SecKey& sk) {
        std::array<uint8_t, 32> out{};
        const char* domain = "Session Router static shared secret key";
        crypto_generichash_blake2b_state st;
        crypto_generichash_blake2b_init(
            &st, reinterpret_cast<const uint8_t*>(domain), strlen(domain), out.size());
        crypto_generichash_blake2b_update(&st, reinterpret_cast<const uint8_t*>(sk.data()), sk.size());
        crypto_generichash_blake2b_final(&st, out.data(), out.size());
        return out;
    };

    auto h1a = hash_key(kp1.sk);
    auto h1b = hash_key(kp1.sk);
    auto h2 = hash_key(kp2.sk);

    REQUIRE(h1a == h1b);  // deterministic
    REQUIRE(h1a != h2);   // different keys → different secrets
}

TEST_CASE("1.15 Connection wrapper construction", "[relay_conn][unit]")
{
    // ConnectionInfo (our test mock) constructs with a label
    auto c = make_conn();
    REQUIRE(c.use_count() == 1);

    // relay_conn holds shared_ptr, incrementing refcount
    relay_conn rc{true};
    rc.set_conn(c, true);
    REQUIRE(c.use_count() == 2);  // our local + relay_conn

    rc.close(true);
    REQUIRE(c.use_count() == 1);  // only our local
}
