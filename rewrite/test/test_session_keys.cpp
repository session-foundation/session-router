#include <catch2/catch_test_macros.hpp>
#include <sr/crypto/session_keys.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::crypto;

TEST_CASE("Session keys: both sides derive same keys (two-phase)", "[crypto][session_keys]")
{
    auto initiator_ed = Ed25519KeyPair::generate();
    auto receiver_ed = Ed25519KeyPair::generate();
    auto initiator_x = X25519KeyPair::generate();
    auto receiver_x = X25519KeyPair::generate();

    // Fake ML-KEM shared secret (both sides must have same value)
    std::array<std::byte, 32> mlkem_ss;
    randombytes_buf(mlkem_ss.data(), mlkem_ss.size());
    std::array<std::byte, 1184> mlkem_pk;
    randombytes_buf(mlkem_pk.data(), mlkem_pk.size());

    auto initiator_rid = initiator_ed.pk;
    auto receiver_rid = receiver_ed.pk;

    // Both sides use the same session tags
    uint32_t tag_i = 0x12345678;
    uint32_t tag_r = 0xABCDEF01;

    auto keys_i = derive_session_keys(
        initiator_x.pk,
        receiver_x.pk,
        initiator_x.sk,
        receiver_x.pk,
        true,  // is_initiator
        mlkem_ss,
        mlkem_pk,
        initiator_rid,
        receiver_rid,
        tag_i,
        tag_r);

    auto keys_r = derive_session_keys(
        initiator_x.pk,
        receiver_x.pk,
        receiver_x.sk,
        initiator_x.pk,
        false,  // is_receiver
        mlkem_ss,
        mlkem_pk,
        initiator_rid,
        receiver_rid,
        tag_i,
        tag_r);

    // Initiator's outbound = receiver's inbound
    REQUIRE(keys_i.key_out == keys_r.key_in);
    // Initiator's inbound = receiver's outbound
    REQUIRE(keys_i.key_in == keys_r.key_out);
}

TEST_CASE("Session keys: initiator out != initiator in", "[crypto][session_keys]")
{
    auto ix = X25519KeyPair::generate();
    auto rx = X25519KeyPair::generate();
    auto ie = Ed25519KeyPair::generate();
    auto re = Ed25519KeyPair::generate();

    std::array<std::byte, 32> mlkem_ss{};
    std::array<std::byte, 1184> mlkem_pk{};

    auto keys = derive_session_keys(ix.pk, rx.pk, ix.sk, rx.pk, true, mlkem_ss, mlkem_pk, ie.pk, re.pk, 1, 2);

    REQUIRE(keys.key_out != keys.key_in);
}

TEST_CASE("Session keys: swapped RouterIDs produce different keys", "[crypto][session_keys]")
{
    auto ix = X25519KeyPair::generate();
    auto rx = X25519KeyPair::generate();
    auto ie = Ed25519KeyPair::generate();
    auto re = Ed25519KeyPair::generate();

    std::array<std::byte, 32> mlkem_ss{};
    std::array<std::byte, 1184> mlkem_pk{};

    auto keys1 = derive_session_keys(ix.pk, rx.pk, ix.sk, rx.pk, true, mlkem_ss, mlkem_pk, ie.pk, re.pk, 1, 2);

    auto keys2 =
        derive_session_keys(ix.pk, rx.pk, ix.sk, rx.pk, true, mlkem_ss, mlkem_pk, re.pk, ie.pk, 1, 2);  // swapped RIDs

    REQUIRE(keys1.key_out != keys2.key_out);
}

TEST_CASE("Session keys: different ML-KEM secret produces different keys", "[crypto][session_keys]")
{
    auto ix = X25519KeyPair::generate();
    auto rx = X25519KeyPair::generate();
    auto ie = Ed25519KeyPair::generate();
    auto re = Ed25519KeyPair::generate();

    std::array<std::byte, 32> ss1{}, ss2{};
    randombytes_buf(ss1.data(), ss1.size());
    randombytes_buf(ss2.data(), ss2.size());
    std::array<std::byte, 1184> mlkem_pk{};

    auto keys1 = derive_session_keys(ix.pk, rx.pk, ix.sk, rx.pk, true, ss1, mlkem_pk, ie.pk, re.pk, 1, 2);

    auto keys2 = derive_session_keys(ix.pk, rx.pk, ix.sk, rx.pk, true, ss2, mlkem_pk, ie.pk, re.pk, 1, 2);

    REQUIRE(keys1.key_out != keys2.key_out);
}

TEST_CASE("Session keys: different session tags produce different keys", "[crypto][session_keys]")
{
    auto ix = X25519KeyPair::generate();
    auto rx = X25519KeyPair::generate();
    auto ie = Ed25519KeyPair::generate();
    auto re = Ed25519KeyPair::generate();

    std::array<std::byte, 32> mlkem_ss{};
    std::array<std::byte, 1184> mlkem_pk{};

    auto keys1 = derive_session_keys(ix.pk, rx.pk, ix.sk, rx.pk, true, mlkem_ss, mlkem_pk, ie.pk, re.pk, 100, 200);

    auto keys2 = derive_session_keys(ix.pk, rx.pk, ix.sk, rx.pk, true, mlkem_ss, mlkem_pk, ie.pk, re.pk, 100, 201);

    REQUIRE(keys1.key_out != keys2.key_out);
}

TEST_CASE("Session keys: two-phase context domain is exactly 23 bytes", "[crypto][session_keys]")
{
    // The domain string "srouter session context" must be exactly 23 bytes
    // to match upstream. This test documents the invariant.
    static constexpr std::string_view domain = "srouter session context";
    REQUIRE(domain.size() == 23);
}
