#include <catch2/catch_test_macros.hpp>

#include <sr/crypto/blind.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::crypto;

TEST_CASE("Blinded key sign and verify", "[crypto][blind]") {
    auto root = Ed25519KeyPair::generate();
    auto bkp = BlindedKeyPair::from_root(root.sk, root.pk, blinding::CLIENT_CONTACT);

    std::vector<std::byte> msg(64);
    randombytes_buf(msg.data(), msg.size());

    auto sig = bkp.sign(msg);
    REQUIRE(blind_verify(msg, sig, bkp.pk));
}

TEST_CASE("Blinded pubkey matches keypair pubkey", "[crypto][blind]") {
    auto root = Ed25519KeyPair::generate();
    auto bkp = BlindedKeyPair::from_root(root.sk, root.pk, blinding::CLIENT_CONTACT);
    auto derived_pk = blind_pubkey(root.pk, blinding::CLIENT_CONTACT);

    REQUIRE(bkp.pk == derived_pk);
}

TEST_CASE("Different domains produce different blinded keys", "[crypto][blind]") {
    auto root = Ed25519KeyPair::generate();
    auto pk1 = blind_pubkey(root.pk, "domain-a");
    auto pk2 = blind_pubkey(root.pk, "domain-b");

    REQUIRE(pk1 != pk2);
}

TEST_CASE("Blinded signature does NOT verify with root pubkey", "[crypto][blind]") {
    auto root = Ed25519KeyPair::generate();
    auto bkp = BlindedKeyPair::from_root(root.sk, root.pk, blinding::CLIENT_CONTACT);

    std::vector<std::byte> msg(32);
    randombytes_buf(msg.data(), msg.size());

    auto sig = bkp.sign(msg);

    // Must NOT verify with root key (proves unlinkability)
    REQUIRE_FALSE(blind_verify(msg, sig, root.pk));
}

TEST_CASE("Blinded key is different from root key", "[crypto][blind]") {
    auto root = Ed25519KeyPair::generate();
    auto blinded = blind_pubkey(root.pk, blinding::CLIENT_CONTACT);

    REQUIRE(blinded != root.pk);
}

TEST_CASE("Same root + same domain = same blinded key", "[crypto][blind]") {
    auto root = Ed25519KeyPair::generate();
    auto pk1 = blind_pubkey(root.pk, blinding::CLIENT_CONTACT);
    auto pk2 = blind_pubkey(root.pk, blinding::CLIENT_CONTACT);

    REQUIRE(pk1 == pk2);
}
