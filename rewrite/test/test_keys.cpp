#include <catch2/catch_test_macros.hpp>

#include <sr/crypto/types.hpp>

using namespace sr::crypto;

TEST_CASE("Ed25519 keygen produces valid keypair", "[crypto][keys]") {
    auto kp = Ed25519KeyPair::generate();
    // Sign and verify
    const unsigned char msg[] = "test message";
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, msg, sizeof(msg) - 1,
                         as_uchar(kp.sk));
    REQUIRE(crypto_sign_verify_detached(sig, msg, sizeof(msg) - 1,
                                        as_uchar(kp.pk)) == 0);
}

TEST_CASE("Ed25519 keypairs are unique", "[crypto][keys]") {
    auto kp1 = Ed25519KeyPair::generate();
    auto kp2 = Ed25519KeyPair::generate();
    REQUIRE(kp1.pk != kp2.pk);
}

TEST_CASE("X25519 keygen produces valid keypair", "[crypto][keys]") {
    auto kp = X25519KeyPair::generate();
    // Basic DH: both sides should agree
    auto kp2 = X25519KeyPair::generate();
    unsigned char shared1[crypto_scalarmult_BYTES];
    unsigned char shared2[crypto_scalarmult_BYTES];
    REQUIRE(crypto_scalarmult(shared1, as_uchar(kp.sk), as_uchar(kp2.pk)) == 0);
    REQUIRE(crypto_scalarmult(shared2, as_uchar(kp2.sk), as_uchar(kp.pk)) == 0);
    REQUIRE(std::memcmp(shared1, shared2, sizeof(shared1)) == 0);
}

TEST_CASE("Ed25519 to X25519 conversion", "[crypto][keys]") {
    auto ed = Ed25519KeyPair::generate();
    auto x = X25519KeyPair::from_ed25519(ed);

    // Verify the converted keypair works for DH
    auto x2 = X25519KeyPair::generate();
    unsigned char shared1[crypto_scalarmult_BYTES];
    unsigned char shared2[crypto_scalarmult_BYTES];
    REQUIRE(crypto_scalarmult(shared1, as_uchar(x.sk), as_uchar(x2.pk)) == 0);
    REQUIRE(crypto_scalarmult(shared2, as_uchar(x2.sk), as_uchar(x.pk)) == 0);
    REQUIRE(std::memcmp(shared1, shared2, sizeof(shared1)) == 0);
}
