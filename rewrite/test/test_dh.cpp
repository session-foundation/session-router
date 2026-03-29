#include <catch2/catch_test_macros.hpp>

#include <sr/crypto/dh.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::crypto;

TEST_CASE("DH both sides derive same shared secret", "[crypto][dh]") {
    auto client = Ed25519KeyPair::generate();
    auto server = Ed25519KeyPair::generate();
    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());

    // Client side
    auto shared_c = dh(client.pk, server.pk, client.sk, server.pk, nonce);
    // Server side
    auto shared_s = dh(client.pk, server.pk, server.sk, client.pk, nonce);

    REQUIRE(shared_c == shared_s);
}

TEST_CASE("DH swapped roles produce different secret", "[crypto][dh]") {
    auto a = Ed25519KeyPair::generate();
    auto b = Ed25519KeyPair::generate();
    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());

    // a=client, b=server
    auto shared1 = dh(a.pk, b.pk, a.sk, b.pk, nonce);
    // b=client, a=server (swapped roles)
    auto shared2 = dh(b.pk, a.pk, a.sk, b.pk, nonce);

    REQUIRE(shared1 != shared2);
}

TEST_CASE("DH different nonce produces different secret", "[crypto][dh]") {
    auto client = Ed25519KeyPair::generate();
    auto server = Ed25519KeyPair::generate();
    Nonce n1, n2;
    randombytes_buf(n1.data(), n1.size());
    randombytes_buf(n2.data(), n2.size());

    auto s1 = dh(client.pk, server.pk, client.sk, server.pk, n1);
    auto s2 = dh(client.pk, server.pk, client.sk, server.pk, n2);

    REQUIRE(s1 != s2);
}

TEST_CASE("XOR nonce derivation is deterministic", "[crypto][dh]") {
    SharedSecret shared;
    randombytes_buf(shared.data(), shared.size());

    auto xn1 = derive_xor_nonce(shared);
    auto xn2 = derive_xor_nonce(shared);

    REQUIRE(xn1 == xn2);
}

TEST_CASE("XOR nonce differs for different shared secrets", "[crypto][dh]") {
    SharedSecret s1, s2;
    randombytes_buf(s1.data(), s1.size());
    randombytes_buf(s2.data(), s2.size());

    REQUIRE(derive_xor_nonce(s1) != derive_xor_nonce(s2));
}

TEST_CASE("BLAKE2b hash basic", "[crypto][dh]") {
    std::vector<std::byte> data(32);
    randombytes_buf(data.data(), data.size());

    auto h1 = blake2b(data);
    auto h2 = blake2b(data);
    REQUIRE(h1 == h2);

    data[0] ^= std::byte{1};
    auto h3 = blake2b(data);
    REQUIRE(h1 != h3);
}

TEST_CASE("BLAKE2b with key differs from without", "[crypto][dh]") {
    std::vector<std::byte> data(32);
    randombytes_buf(data.data(), data.size());
    std::vector<std::byte> key(16);
    randombytes_buf(key.data(), key.size());

    auto h1 = blake2b(data);
    auto h2 = blake2b(data, key);
    REQUIRE(h1 != h2);
}
