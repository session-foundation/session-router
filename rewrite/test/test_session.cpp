#include <catch2/catch_test_macros.hpp>
#include <encoding/bt.hpp>
#include <sr/crypto/session_keys.hpp>
#include <sr/crypto/types.hpp>
#include <sr/session/session.hpp>

using namespace sr::session;
using namespace sr::crypto;

static SessionKeys make_test_keys()
{
    SessionKeys keys;
    randombytes_buf(keys.key_out.data(), keys.key_out.size());
    randombytes_buf(keys.key_in.data(), keys.key_in.size());
    return keys;
}

TEST_CASE("Session encrypt/decrypt round-trip", "[session]")
{
    auto keys_a = make_test_keys();
    // B's inbound = A's outbound, B's outbound = A's inbound
    SessionKeys keys_b;
    keys_b.key_in = keys_a.key_out;
    keys_b.key_out = keys_a.key_in;

    auto tag = random_tag();
    PivotID pivot{};
    randombytes_buf(pivot.data(), pivot.size());

    auto session_a = Session::from_keys(keys_a, tag, pivot);
    auto session_b = Session::from_keys(keys_b, tag, pivot);

    std::vector<std::byte> plaintext(256);
    randombytes_buf(plaintext.data(), plaintext.size());

    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());

    auto msg = session_a.encrypt(plaintext, nonce);
    REQUIRE(msg.size() > plaintext.size());

    // Message ends with [session_tag BE 4] [pivot_id 16]
    REQUIRE(msg.size() >= 4 + 16);

    auto decrypted = session_b.decrypt(msg, nonce);
    REQUIRE(decrypted.has_value());
    REQUIRE(*decrypted == plaintext);
}

TEST_CASE("Session wrong keys fail", "[session]")
{
    auto keys_a = make_test_keys();
    auto keys_wrong = make_test_keys();

    auto tag = random_tag();
    auto session_a = Session::from_keys(keys_a, tag);
    auto session_wrong = Session::from_keys(keys_wrong, tag);

    std::vector<std::byte> plaintext(64);
    randombytes_buf(plaintext.data(), plaintext.size());

    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());

    auto msg = session_a.encrypt(plaintext, nonce);
    auto decrypted = session_wrong.decrypt(msg, nonce);
    REQUIRE_FALSE(decrypted.has_value());
}

TEST_CASE("Session is_established", "[session]")
{
    Session s;
    REQUIRE_FALSE(s.is_established());

    auto keys = make_test_keys();
    auto s2 = Session::from_keys(keys, random_tag());
    REQUIRE(s2.is_established());
}

TEST_CASE("SessionInit BT seal/unseal round-trip", "[session]")
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
    si.pivot_id = {};
    randombytes_buf(si.pivot_id.data(), si.pivot_id.size());

    // seal_for signs internally
    auto sealed = si.seal_for(receiver.pk, initiator.sk);
    REQUIRE(sealed.size() > 0);

    auto unsealed = SessionInit::unseal(sealed, receiver.pk, receiver.sk);
    REQUIRE(unsealed.has_value());
    REQUIRE(unsealed->identity == si.identity);
    REQUIRE(unsealed->x_pubkey == si.x_pubkey);
    REQUIRE(unsealed->tag == si.tag);
    REQUIRE(unsealed->pivot_id == si.pivot_id);
}

TEST_CASE("SessionInit unseal wrong key fails", "[session]")
{
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();
    auto wrong = Ed25519KeyPair::generate();

    SessionInit si;
    si.identity = initiator.pk;
    si.tag = random_tag();

    auto sealed = si.seal_for(receiver.pk, initiator.sk);
    auto unsealed = SessionInit::unseal(sealed, wrong.pk, wrong.sk);
    REQUIRE_FALSE(unsealed.has_value());
}

TEST_CASE("SessionAccept BT seal/unseal round-trip", "[session]")
{
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();
    auto x_kp = X25519KeyPair::generate();

    SessionAccept sa;
    sa.x_pubkey = x_kp.pk;
    sa.tag = random_tag();
    randombytes_buf(sa.mlkem_ciphertext.data(), sa.mlkem_ciphertext.size());

    auto sealed = sa.seal_for(initiator.pk, receiver.sk);
    auto unsealed = SessionAccept::unseal(sealed, initiator.pk, initiator.sk, receiver.pk);
    REQUIRE(unsealed.has_value());
    REQUIRE(unsealed->x_pubkey == sa.x_pubkey);
    REQUIRE(unsealed->tag == sa.tag);
}

TEST_CASE("Session empty plaintext", "[session]")
{
    auto keys_a = make_test_keys();
    SessionKeys keys_b;
    keys_b.key_in = keys_a.key_out;
    keys_b.key_out = keys_a.key_in;

    auto tag = random_tag();
    auto sa = Session::from_keys(keys_a, tag);
    auto sb = Session::from_keys(keys_b, tag);

    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<std::byte> empty;
    auto msg = sa.encrypt(empty, nonce);
    auto dec = sb.decrypt(msg, nonce);
    REQUIRE(dec.has_value());
    REQUIRE(dec->empty());
}

TEST_CASE("Session data message format: tag is big-endian", "[session]")
{
    auto keys = make_test_keys();
    // Tag from uint32 0x01020304 — big-endian on wire: 0x01, 0x02, 0x03, 0x04
    auto tag = uint_to_tag(0x01020304);

    PivotID pivot{};
    auto session = Session::from_keys(keys, tag, pivot);

    Nonce nonce{};
    std::vector<std::byte> plaintext = {std::byte{0xAA}};
    auto msg = session.encrypt(plaintext, nonce);

    // Last 20 bytes = [tag BE 4] [pivot 16]
    REQUIRE(msg.size() >= 20);
    size_t tag_off = msg.size() - 20;

    // Session tag bytes in big-endian order
    REQUIRE(msg[tag_off] == std::byte{0x01});
    REQUIRE(msg[tag_off + 1] == std::byte{0x02});
    REQUIRE(msg[tag_off + 2] == std::byte{0x03});
    REQUIRE(msg[tag_off + 3] == std::byte{0x04});
}

TEST_CASE("SessionControl BT round-trip", "[session]")
{
    SessionControl sc;
    sc.method = "session_close";
    sc.payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};

    auto bt = sc.to_bt();
    REQUIRE(bt.size() > 0);

    auto parsed = SessionControl::from_bt(bt);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->method == "session_close");
    REQUIRE(parsed->payload == sc.payload);
}

TEST_CASE("SessionInit outer BT starts with correct type", "[session]")
{
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();

    SessionInit si;
    si.identity = initiator.pk;
    si.tag = random_tag();

    auto sealed = si.seal_for(receiver.pk, initiator.sk);

    // Should be a BT dict starting with 'd'
    REQUIRE(sealed.size() > 0);
    REQUIRE(sealed[0] == std::byte{'d'});

    // Parse and verify the type field
    auto sv = sr::encoding::to_sv(sealed);
    oxenc::bt_dict_consumer dc{sv};
    std::string empty_key{""};
    bool found = dc.skip_until(empty_key);
    REQUIRE(found);
    auto type_str = dc.consume_string();
    REQUIRE(type_str == "i");
}

TEST_CASE("SessionAccept outer BT starts with correct type", "[session]")
{
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();
    auto x_kp = X25519KeyPair::generate();

    SessionAccept sa;
    sa.x_pubkey = x_kp.pk;
    sa.tag = random_tag();
    randombytes_buf(sa.mlkem_ciphertext.data(), sa.mlkem_ciphertext.size());

    auto sealed = sa.seal_for(initiator.pk, receiver.sk);

    REQUIRE(sealed.size() > 0);
    REQUIRE(sealed[0] == std::byte{'d'});

    auto sv = sr::encoding::to_sv(sealed);
    oxenc::bt_dict_consumer dc{sv};
    std::string empty_key{""};
    bool found = dc.skip_until(empty_key);
    REQUIRE(found);
    auto type_str = dc.consume_string();
    REQUIRE(type_str == "a");
}
