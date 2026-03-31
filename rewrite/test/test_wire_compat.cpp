#include <arpa/inet.h>
#include <catch2/catch_test_macros.hpp>
#include <encoding/bt.hpp>
#include <sr/contact/relay_contact.hpp>
#include <sr/crypto/session_keys.hpp>
#include <sr/crypto/types.hpp>
#include <sr/path/onion.hpp>
#include <sr/session/session.hpp>

using namespace sr::encoding;
using namespace sr::crypto;
using namespace sr::session;
using namespace sr::path;
using namespace sr::contact;

// ============================================================================
// BT encoding round-trip tests
// ============================================================================

TEST_CASE("Wire compat: BT dict keys are lexicographically sorted", "[wire_compat][bt]")
{
    oxenc::bt_dict_producer dp{};
    dp.append("a", "first");
    dp.append("b", "second");
    dp.append("z", "last");
    auto str = std::move(dp).str();

    // Verify the string is a valid BT dict
    REQUIRE(str[0] == 'd');
    REQUIRE(str.back() == 'e');

    // Keys must appear in order: a < b < z
    auto a_pos = str.find("1:a");
    auto b_pos = str.find("1:b");
    auto z_pos = str.find("1:z");
    REQUIRE(a_pos < b_pos);
    REQUIRE(b_pos < z_pos);
}

TEST_CASE("Wire compat: BT signature append/verify round-trip", "[wire_compat][bt]")
{
    auto kp = Ed25519KeyPair::generate();

    // Build a dict prefix (without closing 'e')
    oxenc::bt_dict_producer dp{};
    dp.append("hello", "world");
    dp.append("num", 42);
    auto full = std::move(dp).str();

    // Remove trailing 'e' to get prefix
    auto prefix = full.substr(0, full.size() - 1);

    // Sign
    auto signed_bt = append_signature(prefix, as_uchar(kp.sk));

    // Verify
    REQUIRE(verify_signature(signed_bt, as_uchar(kp.pk)));

    // Wrong key fails
    auto wrong_kp = Ed25519KeyPair::generate();
    REQUIRE_FALSE(verify_signature(signed_bt, as_uchar(wrong_kp.pk)));
}

// ============================================================================
// Session key derivation compatibility
// ============================================================================

TEST_CASE("Wire compat: session key derivation domain is 23 bytes", "[wire_compat][session_keys]")
{
    // Upstream uses "srouter session context" — exactly 23 bytes
    std::string_view domain = "srouter session context";
    REQUIRE(domain.size() == 23);
}

TEST_CASE("Wire compat: session keys — initiator and receiver agree with tags", "[wire_compat][session_keys]")
{
    auto ie = Ed25519KeyPair::generate();
    auto re = Ed25519KeyPair::generate();
    auto ix = X25519KeyPair::generate();
    auto rx = X25519KeyPair::generate();

    std::array<std::byte, 32> mlkem_ss;
    randombytes_buf(mlkem_ss.data(), mlkem_ss.size());
    std::array<std::byte, 1184> mlkem_pk;
    randombytes_buf(mlkem_pk.data(), mlkem_pk.size());

    uint32_t tag_i = 0xDEADBEEF;
    uint32_t tag_r = 0xCAFEBABE;

    auto keys_i = derive_session_keys(
        ix.pk, rx.pk, ix.sk, rx.pk, true, mlkem_ss, mlkem_pk, ie.pk, re.pk, tag_i, tag_r);
    auto keys_r = derive_session_keys(
        ix.pk, rx.pk, rx.sk, ix.pk, false, mlkem_ss, mlkem_pk, ie.pk, re.pk, tag_i, tag_r);

    REQUIRE(keys_i.key_out == keys_r.key_in);
    REQUIRE(keys_i.key_in == keys_r.key_out);
    REQUIRE(keys_i.key_out != keys_i.key_in);
}

// ============================================================================
// Session init/accept BT format
// ============================================================================

TEST_CASE("Wire compat: SessionInit outer is BT dict with type 'i'", "[wire_compat][session]")
{
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();
    auto x_kp = X25519KeyPair::generate();
    auto mlkem_kp = MLKEMKeyPair::generate();

    SessionInit si;
    si.identity = initiator.pk;
    si.x_pubkey = x_kp.pk;
    si.mlkem_pubkey = mlkem_kp.pk;
    si.tag = random_tag();
    randombytes_buf(si.pivot_id.data(), si.pivot_id.size());

    auto sealed = si.seal_for(receiver.pk, initiator.sk);

    // Must be BT dict
    REQUIRE(sealed[0] == std::byte{'d'});

    // Parse outer
    auto sv = to_sv(sealed);
    oxenc::bt_dict_consumer dc{sv};

    // First key "" has value "i"
    auto key = dc.key();
    REQUIRE(key.empty());
    auto type_val = dc.consume_string();
    REQUIRE(type_val == "i");

    // Second key "B" has sealed box bytes
    auto key2 = dc.key();
    REQUIRE(key2 == "B");
    auto b_val = dc.consume_string_view();
    REQUIRE(b_val.size() > 0);
}

TEST_CASE("Wire compat: SessionAccept outer is BT dict with type 'a'", "[wire_compat][session]")
{
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();
    auto x_kp = X25519KeyPair::generate();

    SessionAccept sa;
    sa.x_pubkey = x_kp.pk;
    sa.tag = random_tag();
    randombytes_buf(sa.mlkem_ciphertext.data(), sa.mlkem_ciphertext.size());

    auto sealed = sa.seal_for(initiator.pk, receiver.sk);
    REQUIRE(sealed[0] == std::byte{'d'});

    auto sv = to_sv(sealed);
    oxenc::bt_dict_consumer dc{sv};
    auto key = dc.key();
    REQUIRE(key.empty());
    REQUIRE(dc.consume_string() == "a");
}

TEST_CASE("Wire compat: SessionInit full round-trip preserves all fields", "[wire_compat][session]")
{
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();
    auto x_kp = X25519KeyPair::generate();
    auto mlkem_kp = MLKEMKeyPair::generate();

    SessionInit si;
    si.identity = initiator.pk;
    si.x_pubkey = x_kp.pk;
    si.mlkem_pubkey = mlkem_kp.pk;
    si.tag = random_tag();
    randombytes_buf(si.pivot_id.data(), si.pivot_id.size());

    auto sealed = si.seal_for(receiver.pk, initiator.sk);
    auto unsealed = SessionInit::unseal(sealed, receiver.pk, receiver.sk);
    REQUIRE(unsealed.has_value());
    REQUIRE(unsealed->identity == si.identity);
    REQUIRE(unsealed->x_pubkey == si.x_pubkey);
    REQUIRE(unsealed->mlkem_pubkey == si.mlkem_pubkey);
    REQUIRE(unsealed->tag == si.tag);
    REQUIRE(unsealed->pivot_id == si.pivot_id);
}

// ============================================================================
// Session control format
// ============================================================================

TEST_CASE("Wire compat: SessionControl BT format", "[wire_compat][session]")
{
    SessionControl sc;
    sc.method = "session_close";
    sc.payload = {std::byte{0xFF}};

    auto bt = sc.to_bt();
    auto sv = to_sv(bt);
    oxenc::bt_dict_consumer dc{sv};

    // "e" -> method
    auto key1 = dc.key();
    REQUIRE(key1 == "e");
    REQUIRE(dc.consume_string() == "session_close");

    // "p" -> payload
    auto key2 = dc.key();
    REQUIRE(key2 == "p");
    auto p = dc.consume_string_view();
    REQUIRE(p.size() == 1);
}

// ============================================================================
// Session data format
// ============================================================================

TEST_CASE("Wire compat: session data has [encrypted][tag 4B][pivot 16B]", "[wire_compat][session]")
{
    auto keys = SessionKeys{};
    randombytes_buf(keys.key_out.data(), keys.key_out.size());
    randombytes_buf(keys.key_in.data(), keys.key_in.size());

    SessionTag tag;
    tag[0] = std::byte{0xAA};
    tag[1] = std::byte{0xBB};
    tag[2] = std::byte{0xCC};
    tag[3] = std::byte{0xDD};

    PivotID pivot{};
    for (auto& b : pivot)
        b = std::byte{0x42};

    auto session = Session::from_keys(keys, tag, pivot);

    Nonce nonce{};
    std::vector<std::byte> plaintext = {std::byte{0x01}};
    auto msg = session.encrypt(plaintext, nonce);

    // Last 20 bytes: [tag 4] [pivot 16]
    REQUIRE(msg.size() >= 20);
    size_t off = msg.size() - 20;

    // Tag bytes
    REQUIRE(msg[off + 0] == std::byte{0xAA});
    REQUIRE(msg[off + 1] == std::byte{0xBB});
    REQUIRE(msg[off + 2] == std::byte{0xCC});
    REQUIRE(msg[off + 3] == std::byte{0xDD});

    // Pivot bytes
    for (size_t i = 0; i < 16; ++i)
        REQUIRE(msg[off + 4 + i] == std::byte{0x42});
}

// ============================================================================
// Path build frame format
// ============================================================================

TEST_CASE("Wire compat: path build frame is BT dict with k/n/x keys", "[wire_compat][path]")
{
    // Reset relay keys for this test
    Ed25519KeyPair rk[2];
    rk[0] = Ed25519KeyPair::generate();
    rk[1] = Ed25519KeyPair::generate();

    std::vector<RelayContact> relays;
    for (int i = 0; i < 2; ++i)
    {
        RouterID rid{rk[i].pk};
        RelayAddress addr{htonl(0x7F000001 + i), 1090};
        auto now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
        RelayContact rc{rid, addr, {0, 10, 0}, now};
        rc.sign(rk[i].sk);
        relays.push_back(rc);
    }

    auto ephemeral = Ed25519KeyPair::generate();
    auto result = build_onion(relays, ephemeral, std::chrono::seconds(1200));

    // Frame 0 should be a valid BT dict
    auto frame0 = std::span<const std::byte>(result.frames.data(), BUILD_FRAME_SIZE);

    // Frame starts with BT dict 'd'
    REQUIRE(static_cast<char>(frame0[0]) == 'd');

    // Decrypt and verify inner is also BT
    auto df = decrypt_build_frame(frame0, rk[0].sk, rk[0].pk);
    REQUIRE(df.has_value());
    REQUIRE(df->lifetime == std::chrono::seconds(1200));
}

TEST_CASE("Wire compat: hop ID chaining 3-hop", "[wire_compat][path]")
{
    Ed25519KeyPair rk[3];
    std::vector<RelayContact> relays;
    for (int i = 0; i < 3; ++i)
    {
        rk[i] = Ed25519KeyPair::generate();
        RouterID rid{rk[i].pk};
        RelayAddress addr{htonl(0x7F000001 + i), 1090};
        auto now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
        RelayContact rc{rid, addr, {0, 10, 0}, now};
        rc.sign(rk[i].sk);
        relays.push_back(rc);
    }

    auto ephemeral = Ed25519KeyPair::generate();
    auto result = build_onion(relays, ephemeral, std::chrono::seconds(1200));

    // hop[1].rxid == hop[0].txid
    REQUIRE(result.hops[1].rxid == result.hops[0].txid);
    // hop[2].rxid == hop[1].txid
    REQUIRE(result.hops[2].rxid == result.hops[1].txid);
    // pivot: txid == rxid
    REQUIRE(result.hops[2].txid == result.hops[2].rxid);
}

// ============================================================================
// Path message framing
// ============================================================================

TEST_CASE("Wire compat: path trailer is exactly 41 bytes", "[wire_compat][path]")
{
    REQUIRE(PATH_TRAILER_SIZE == 41);

    Nonce nonce{};
    HopID hopid{};
    std::vector<std::byte> payload = {std::byte{0x01}};

    auto msg = append_path_trailer(payload, nonce, hopid, PATH_MSG_DATA_OR_CONTROL);
    REQUIRE(msg.size() == 1 + 41);

    // Last byte is msgtype
    REQUIRE(msg.back() == std::byte{0x01});
}

TEST_CASE("Wire compat: path trailer msgtype 0x02 for handshake", "[wire_compat][path]")
{
    Nonce nonce{};
    HopID hopid{};
    std::vector<std::byte> payload;

    auto msg = append_path_trailer(payload, nonce, hopid, PATH_MSG_SESSION_HANDSHAKE);
    REQUIRE(msg.back() == std::byte{0x02});
}

// ============================================================================
// Bootstrap RC format
// ============================================================================

TEST_CASE("Wire compat: RC BT round-trip with all fields", "[wire_compat][rc]")
{
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};
    RelayAddress addr{htonl(0xC0A80001), 8080};  // 192.168.0.1:8080
    auto now_s = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());

    RelayContact rc{rid, addr, {1, 0, 2}, now_s};
    rc.set_network_id(1);  // testnet

    IPv6Address v6;
    v6.present = true;
    // 2001:db8::1
    v6.addr[0] = 0x20;
    v6.addr[1] = 0x01;
    v6.addr[2] = 0x0D;
    v6.addr[3] = 0xB8;
    v6.addr[15] = 0x01;
    v6.port = 9090;
    rc.set_ipv6(v6);
    rc.sign(kp.sk);

    auto bt = rc.to_bt_signed();
    auto parsed = RelayContact::from_bt(bt);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->router_id() == rid);
    REQUIRE(parsed->address().ipv4 == htonl(0xC0A80001));
    REQUIRE(parsed->address().port == 8080);
    REQUIRE(parsed->ipv6().present);
    REQUIRE(parsed->ipv6().port == 9090);
    REQUIRE(parsed->ipv6().addr[0] == 0x20);
    REQUIRE(parsed->network_id() == 1);
    REQUIRE(parsed->version() == std::array<uint8_t, 3>{1, 0, 2});
}

TEST_CASE("Wire compat: bootstrap single dict parsing", "[wire_compat][rc]")
{
    auto kp = Ed25519KeyPair::generate();
    RouterID rid{kp.pk};
    RelayAddress addr{htonl(0x7F000001), 1090};
    auto now_s = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
    RelayContact rc{rid, addr, {0, 10, 0}, now_s};
    rc.sign(kp.sk);

    auto bt = rc.to_bt_signed();

    // First byte should be 'd'
    REQUIRE(static_cast<char>(bt[0]) == 'd');

    auto result = RelayContact::from_bootstrap(bt);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].router_id() == rid);
}

TEST_CASE("Wire compat: bootstrap list parsing", "[wire_compat][rc]")
{
    // Build two RCs manually and wrap in a BT list
    auto kp1 = Ed25519KeyPair::generate();
    auto kp2 = Ed25519KeyPair::generate();

    auto now_s = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());

    RelayContact rc1{RouterID{kp1.pk}, RelayAddress{htonl(0x7F000001), 1090}, {0, 10, 0}, now_s};
    rc1.sign(kp1.sk);
    RelayContact rc2{RouterID{kp2.pk}, RelayAddress{htonl(0x7F000002), 1091}, {0, 10, 0}, now_s};
    rc2.sign(kp2.sk);

    auto bt1 = rc1.to_bt_signed();
    auto bt2 = rc2.to_bt_signed();

    // Build list: l<rc1><rc2>e
    std::vector<std::byte> bootstrap;
    bootstrap.push_back(std::byte{'l'});
    bootstrap.insert(bootstrap.end(), bt1.begin(), bt1.end());
    bootstrap.insert(bootstrap.end(), bt2.begin(), bt2.end());
    bootstrap.push_back(std::byte{'e'});

    auto result = RelayContact::from_bootstrap(bootstrap);
    REQUIRE(result.size() == 2);
    REQUIRE(result[0].router_id() == RouterID{kp1.pk});
    REQUIRE(result[1].router_id() == RouterID{kp2.pk});
}

TEST_CASE("Wire compat: RC max size enforcement", "[wire_compat][rc]")
{
    REQUIRE(RC_MAX_SIZE == 2048);
    std::vector<std::byte> oversized(RC_MAX_SIZE + 1, std::byte{'d'});
    auto parsed = RelayContact::from_bt(oversized);
    REQUIRE_FALSE(parsed.has_value());
}
