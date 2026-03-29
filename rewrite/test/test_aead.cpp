#include <catch2/catch_test_macros.hpp>
#include <sodium.h>
#include <sr/crypto/aead.hpp>
#include <sr/crypto/types.hpp>

using namespace sr::crypto;

static SymmetricKey random_key()
{
    sodium_init_once();
    SymmetricKey k;
    randombytes_buf(k.data(), k.size());
    return k;
}

static Nonce random_nonce()
{
    Nonce n;
    randombytes_buf(n.data(), n.size());
    return n;
}

TEST_CASE("AEAD encrypt/decrypt round-trip", "[crypto][aead]")
{
    auto key = random_key();
    auto nonce = random_nonce();
    std::vector<std::byte> plaintext(100);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto ct = aead_encrypt(plaintext, key, nonce);
    REQUIRE(ct.size() == plaintext.size() + AEAD_TAG_SIZE);

    auto pt = aead_decrypt(ct, key, nonce);
    REQUIRE(pt.has_value());
    REQUIRE(*pt == plaintext);
}

TEST_CASE("AEAD wrong key fails", "[crypto][aead]")
{
    auto key1 = random_key();
    auto key2 = random_key();
    auto nonce = random_nonce();
    std::vector<std::byte> plaintext(64);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto ct = aead_encrypt(plaintext, key1, nonce);
    auto pt = aead_decrypt(ct, key2, nonce);
    REQUIRE_FALSE(pt.has_value());
}

TEST_CASE("AEAD tampered ciphertext fails", "[crypto][aead]")
{
    auto key = random_key();
    auto nonce = random_nonce();
    std::vector<std::byte> plaintext(64);
    randombytes_buf(plaintext.data(), plaintext.size());

    auto ct = aead_encrypt(plaintext, key, nonce);
    ct[10] ^= std::byte{0xFF};  // flip one byte

    auto pt = aead_decrypt(ct, key, nonce);
    REQUIRE_FALSE(pt.has_value());
}

TEST_CASE("AEAD too-short ciphertext fails", "[crypto][aead]")
{
    auto key = random_key();
    auto nonce = random_nonce();
    std::vector<std::byte> short_ct(AEAD_TAG_SIZE - 1);

    auto pt = aead_decrypt(short_ct, key, nonce);
    REQUIRE_FALSE(pt.has_value());
}

TEST_CASE("AEAD inplace matches allocating", "[crypto][aead]")
{
    auto key = random_key();
    auto nonce = random_nonce();
    std::vector<std::byte> plaintext(80);
    randombytes_buf(plaintext.data(), plaintext.size());

    // Allocating
    auto ct_alloc = aead_encrypt(plaintext, key, nonce);

    // Inplace
    std::vector<std::byte> buf(plaintext.size() + AEAD_TAG_SIZE);
    std::copy(plaintext.begin(), plaintext.end(), buf.begin());
    aead_encrypt_inplace(buf, plaintext.size(), key, nonce);

    REQUIRE(buf == ct_alloc);
}

TEST_CASE("xchacha20 stream cipher round-trip", "[crypto][aead]")
{
    auto key = random_key();
    auto nonce = random_nonce();
    std::vector<std::byte> original(128);
    randombytes_buf(original.data(), original.size());

    std::vector<std::byte> buf = original;
    xchacha20_inplace(buf, key, nonce);
    REQUIRE(buf != original);  // encrypted

    xchacha20_inplace(buf, key, nonce);
    REQUIRE(buf == original);  // XOR cipher: encrypt twice = plaintext
}

TEST_CASE("AEAD empty plaintext", "[crypto][aead]")
{
    auto key = random_key();
    auto nonce = random_nonce();
    std::vector<std::byte> empty;

    auto ct = aead_encrypt(empty, key, nonce);
    REQUIRE(ct.size() == AEAD_TAG_SIZE);

    auto pt = aead_decrypt(ct, key, nonce);
    REQUIRE(pt.has_value());
    REQUIRE(pt->empty());
}
