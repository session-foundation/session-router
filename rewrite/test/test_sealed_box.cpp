#include <catch2/catch_test_macros.hpp>
#include <sr/crypto/sealed_box.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::crypto;

TEST_CASE("Sealed box round-trip", "[crypto][sealed_box]")
{
    auto kp = Ed25519KeyPair::generate();
    std::vector<std::byte> plaintext(128);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto ct = seal(plaintext, kp.pk);
    REQUIRE(ct.size() == plaintext.size() + SEAL_OVERHEAD);

    auto pt = unseal(ct, kp.pk, kp.sk);
    REQUIRE(pt.has_value());
    REQUIRE(*pt == plaintext);
}

TEST_CASE("Sealed box wrong key fails", "[crypto][sealed_box]")
{
    auto sender_target = Ed25519KeyPair::generate();
    auto wrong_key = Ed25519KeyPair::generate();
    std::vector<std::byte> plaintext(64);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto ct = seal(plaintext, sender_target.pk);
    auto pt = unseal(ct, wrong_key.pk, wrong_key.sk);
    REQUIRE_FALSE(pt.has_value());
}

TEST_CASE("Sealed box tampered ciphertext fails", "[crypto][sealed_box]")
{
    auto kp = Ed25519KeyPair::generate();
    std::vector<std::byte> plaintext(64);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto ct = seal(plaintext, kp.pk);
    ct[SEAL_OVERHEAD / 2] ^= std::byte{0xFF};

    auto pt = unseal(ct, kp.pk, kp.sk);
    REQUIRE_FALSE(pt.has_value());
}

TEST_CASE("Sealed box truncated ciphertext fails", "[crypto][sealed_box]")
{
    auto kp = Ed25519KeyPair::generate();
    std::vector<std::byte> short_ct(SEAL_OVERHEAD - 1);

    auto pt = unseal(short_ct, kp.pk, kp.sk);
    REQUIRE_FALSE(pt.has_value());
}

TEST_CASE("Sealed box empty plaintext", "[crypto][sealed_box]")
{
    auto kp = Ed25519KeyPair::generate();
    std::vector<std::byte> empty;

    auto ct = seal(empty, kp.pk);
    REQUIRE(ct.size() == SEAL_OVERHEAD);

    auto pt = unseal(ct, kp.pk, kp.sk);
    REQUIRE(pt.has_value());
    REQUIRE(pt->empty());
}
