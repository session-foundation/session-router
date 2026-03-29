#include <catch2/catch_test_macros.hpp>

#include <sr/path/path.hpp>
#include <sr/crypto/dh.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::path;
using namespace sr::crypto;

static Hop make_hop() {
    auto kp = Ed25519KeyPair::generate();
    SharedSecret ss;
    randombytes_buf(ss.data(), ss.size());
    auto xn = derive_xor_nonce(ss);
    return Hop{
        sr::contact::RouterID{kp.pk},
        ss, xn,
        random_hop_id(), random_hop_id()
    };
}

TEST_CASE("Path encrypt/decrypt round-trip", "[path]") {
    std::vector<Hop> hops = {make_hop(), make_hop(), make_hop()};
    Path path{hops};

    std::vector<std::byte> plaintext(128);
    randombytes_buf(plaintext.data(), plaintext.size());

    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());

    auto encrypted = path.encrypt_data(plaintext, nonce);
    REQUIRE(encrypted.size() == plaintext.size());
    REQUIRE(encrypted != plaintext);

    // Simulate relay-side peeling: each hop peels one layer
    // Forward order, XOR nonce between hops
    Nonce relay_nonce = nonce;
    for (size_t i = 0; i < hops.size(); ++i) {
        SymmetricKey key;
        std::memcpy(key.data(), hops[i].shared_secret.data(), 32);
        xchacha20_inplace(encrypted, key, relay_nonce);
        if (i + 1 < hops.size()) {
            for (size_t j = 0; j < relay_nonce.size(); ++j)
                relay_nonce[j] ^= hops[i].xor_nonce[j];
        }
    }

    REQUIRE(encrypted == plaintext);
}

TEST_CASE("Path decrypt reverses encrypt", "[path]") {
    std::vector<Hop> hops = {make_hop(), make_hop()};
    Path path{hops};

    std::vector<std::byte> original(64);
    randombytes_buf(original.data(), original.size());
    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());

    // Simulate relay-side onioning (for return path):
    // Each relay encrypts in forward order
    std::vector<std::byte> data = original;
    Nonce relay_nonce = nonce;
    for (size_t i = 0; i < hops.size(); ++i) {
        SymmetricKey key;
        std::memcpy(key.data(), hops[i].shared_secret.data(), 32);
        xchacha20_inplace(data, key, relay_nonce);
        if (i + 1 < hops.size()) {
            for (size_t j = 0; j < relay_nonce.size(); ++j)
                relay_nonce[j] ^= hops[i].xor_nonce[j];
        }
    }

    // Client decrypts
    Nonce dec_nonce = nonce;
    auto result = path.decrypt_data(data, dec_nonce);
    REQUIRE(result.has_value());
    REQUIRE(*result == original);
}

TEST_CASE("Path single hop encrypt/decrypt", "[path]") {
    std::vector<Hop> hops = {make_hop()};
    Path path{hops};

    std::vector<std::byte> plaintext(32);
    randombytes_buf(plaintext.data(), plaintext.size());
    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());

    auto encrypted = path.encrypt_data(plaintext, nonce);

    // Single hop peel
    SymmetricKey key;
    std::memcpy(key.data(), hops[0].shared_secret.data(), 32);
    xchacha20_inplace(encrypted, key, nonce);

    REQUIRE(encrypted == plaintext);
}

TEST_CASE("Path expiry", "[path]") {
    std::vector<Hop> hops = {make_hop()};
    auto old = std::chrono::steady_clock::now() - std::chrono::minutes(25);
    Path path{hops, old};

    REQUIRE(path.is_expired(std::chrono::steady_clock::now()));
}

TEST_CASE("Path not expired when fresh", "[path]") {
    std::vector<Hop> hops = {make_hop()};
    Path path{hops};

    REQUIRE_FALSE(path.is_expired(std::chrono::steady_clock::now()));
}

TEST_CASE("Path established flag", "[path]") {
    Path path{std::vector<Hop>{make_hop()}};
    REQUIRE_FALSE(path.is_established());
    path.set_established();
    REQUIRE(path.is_established());
}
