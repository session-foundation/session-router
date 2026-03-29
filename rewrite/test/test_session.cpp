#include <catch2/catch_test_macros.hpp>

#include <sr/session/session.hpp>
#include <sr/crypto/session_keys.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::session;
using namespace sr::crypto;

static SessionKeys make_test_keys() {
    SessionKeys keys;
    randombytes_buf(keys.key_out.data(), keys.key_out.size());
    randombytes_buf(keys.key_in.data(), keys.key_in.size());
    return keys;
}

TEST_CASE("Session encrypt/decrypt round-trip", "[session]") {
    auto keys_a = make_test_keys();
    // B's inbound = A's outbound, B's outbound = A's inbound
    SessionKeys keys_b;
    keys_b.key_in = keys_a.key_out;
    keys_b.key_out = keys_a.key_in;

    auto tag = random_tag();
    auto session_a = Session::from_keys(keys_a, tag);
    auto session_b = Session::from_keys(keys_b, tag);

    std::vector<std::byte> plaintext(256);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto msg = session_a.encrypt(plaintext);
    REQUIRE(msg.size() > plaintext.size());

    auto decrypted = session_b.decrypt(msg);
    REQUIRE(decrypted.has_value());
    REQUIRE(*decrypted == plaintext);
}

TEST_CASE("Session wrong keys fail", "[session]") {
    auto keys_a = make_test_keys();
    auto keys_wrong = make_test_keys();

    auto tag = random_tag();
    auto session_a = Session::from_keys(keys_a, tag);
    auto session_wrong = Session::from_keys(keys_wrong, tag);

    std::vector<std::byte> plaintext(64);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto msg = session_a.encrypt(plaintext);
    auto decrypted = session_wrong.decrypt(msg);
    REQUIRE_FALSE(decrypted.has_value());
}

TEST_CASE("Session is_established", "[session]") {
    Session s;
    REQUIRE_FALSE(s.is_established());

    auto keys = make_test_keys();
    auto s2 = Session::from_keys(keys, random_tag());
    REQUIRE(s2.is_established());
}

TEST_CASE("SessionInit seal/unseal round-trip", "[session]") {
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();
    auto x_kp = X25519KeyPair::generate();
    auto mlkem_kp = MLKEMKeyPair::generate();

    SessionInit si;
    si.identity = initiator.pk;
    si.x_pubkey = x_kp.pk;
    si.mlkem_pubkey = mlkem_kp.pk;
    si.tag = random_tag();
    // Sign identity proof
    crypto_sign_detached(
        as_uchar(si.signature), nullptr,
        as_uchar(si.identity), si.identity.size(),
        as_uchar(initiator.sk));

    auto sealed = si.seal_for(receiver.pk, initiator.sk);
    REQUIRE(sealed.size() > 0);

    auto unsealed = SessionInit::unseal(sealed, receiver.pk, receiver.sk);
    REQUIRE(unsealed.has_value());
    REQUIRE(unsealed->identity == si.identity);
    REQUIRE(unsealed->x_pubkey == si.x_pubkey);
    REQUIRE(unsealed->tag == si.tag);
}

TEST_CASE("SessionInit unseal wrong key fails", "[session]") {
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

TEST_CASE("SessionAccept seal/unseal round-trip", "[session]") {
    auto initiator = Ed25519KeyPair::generate();
    auto receiver = Ed25519KeyPair::generate();
    auto x_kp = X25519KeyPair::generate();

    SessionAccept sa;
    sa.x_pubkey = x_kp.pk;
    sa.tag = random_tag();
    // Fill ciphertext and signature with random for test
    randombytes_buf(sa.mlkem_ciphertext.data(), sa.mlkem_ciphertext.size());
    crypto_sign_detached(
        as_uchar(sa.signature), nullptr,
        as_uchar(sa.x_pubkey), sa.x_pubkey.size(),
        as_uchar(receiver.sk));

    auto sealed = sa.seal_for(initiator.pk, receiver.sk);
    auto unsealed = SessionAccept::unseal(sealed, initiator.pk, initiator.sk);
    REQUIRE(unsealed.has_value());
    REQUIRE(unsealed->x_pubkey == sa.x_pubkey);
    REQUIRE(unsealed->tag == sa.tag);
}

TEST_CASE("Session empty plaintext", "[session]") {
    auto keys_a = make_test_keys();
    SessionKeys keys_b;
    keys_b.key_in = keys_a.key_out;
    keys_b.key_out = keys_a.key_in;

    auto tag = random_tag();
    auto sa = Session::from_keys(keys_a, tag);
    auto sb = Session::from_keys(keys_b, tag);

    std::vector<std::byte> empty;
    auto msg = sa.encrypt(empty);
    auto dec = sb.decrypt(msg);
    REQUIRE(dec.has_value());
    REQUIRE(dec->empty());
}
