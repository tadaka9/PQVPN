#include <catch2/catch_test_macros.hpp>

#include "tunnel_aead.hpp"

namespace {

// Known-answer vectors for pqvpn::tunnel_encrypt / tunnel_decrypt. They were
// produced with an independent AES-GCM implementation (Python `cryptography`
// AESGCM, the same library main.py uses) and verified to round-trip before
// being recorded here, so a regression in the OpenSSL path or in the wire
// layout (nonce shape, AAD binding, tag position) fails byte-for-byte.

const std::vector<uint8_t> key_256 = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

// session_iv(4) + big-endian counter(7), the main.py nonce layout.
const std::vector<uint8_t> nonce_256 = {
    0xa5, 0xc3, 0x3b, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};

// Outer frame header bound as AAD: version(1) + type TUNNEL_DATA(5) +
// session hint(8) + circuit id(4) + payload length(2).
const std::vector<uint8_t> aad_256 = {
    0x01, 0x05, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
    0x00, 0x00, 0x30, 0x39, 0x00, 0x0c};

const std::vector<uint8_t> plaintext_256 = {
    0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef, 0x90, 0x01, 0x00, 0x01};

const std::vector<uint8_t> sealed_256 = {
    0xfe, 0xc6, 0x4d, 0xb5, 0xe5, 0x82, 0x84, 0xed, 0xd6, 0x60, 0x95, 0x59,
    0x32, 0x30, 0xa5, 0x57, 0xbe, 0x77, 0xa7, 0xb2, 0x05, 0x1d, 0x98, 0x2a,
    0xcd, 0xb5, 0xa5, 0xad};

const std::vector<uint8_t> key_128 = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f};

const std::vector<uint8_t> nonce_128 = {
    0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

// Relay layer header bound as AAD: version(1) + type RELAY(7) + next-hop
// hash(8) + circuit id(4) + payload length(2).
const std::vector<uint8_t> aad_128 = {
    0x01, 0x07, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x10};

// next-hop hash(8) + inner content, the relay plaintext shape.
const std::vector<uint8_t> plaintext_128 = {
    0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13, 0xde, 0xad, 0xbe, 0xef};

const std::vector<uint8_t> sealed_128 = {
    0x03, 0x61, 0xa3, 0xe6, 0xe3, 0x46, 0xd5, 0x59, 0x5f, 0x49, 0xd3, 0x00,
    0xdc, 0x5f, 0xe8, 0xbf, 0xd3, 0xfd, 0xef, 0x5d, 0x3c, 0x9b, 0xcc, 0x27,
    0xf2, 0x1e, 0x3b, 0xf0};

} // namespace

TEST_CASE("tunnel_nonce lays out the IV prefix and big-endian counter", "[tunnel][aead][kat]") {
    const std::vector<uint8_t> iv{
        0xa5, 0xc3, 0x3b, 0x9e, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};

    REQUIRE(pqvpn::tunnel_nonce(iv, 7) ==
        (std::vector<uint8_t>{0xa5, 0xc3, 0x3b, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07}));
    REQUIRE(pqvpn::tunnel_nonce(iv, 1) ==
        (std::vector<uint8_t>{0xa5, 0xc3, 0x3b, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}));
    REQUIRE(pqvpn::tunnel_nonce(iv, 0xffffffffffffffffULL) ==
        (std::vector<uint8_t>{0xa5, 0xc3, 0x3b, 0x9e, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));

    SECTION("invalid nonce state is rejected") {
        REQUIRE_THROWS_AS(pqvpn::tunnel_nonce(iv, 0), std::invalid_argument);
        const std::vector<uint8_t> short_iv{0xa5, 0xc3, 0x3b};
        REQUIRE_THROWS_AS(pqvpn::tunnel_nonce(short_iv, 1), std::invalid_argument);
    }
}

TEST_CASE("tunnel_encrypt matches AES-256-GCM known-answer vectors", "[tunnel][aead][kat]") {
    const auto sealed = pqvpn::tunnel_encrypt(
        std::span<const uint8_t>(plaintext_256), key_256, nonce_256,
        std::span<const uint8_t>(aad_256));

    REQUIRE(sealed == sealed_256);

    SECTION("decrypts back to the original plaintext") {
        const auto opened = pqvpn::tunnel_decrypt(
            std::span<const uint8_t>(sealed_256), key_256, nonce_256,
            std::span<const uint8_t>(aad_256));
        REQUIRE(opened);
        REQUIRE(*opened == plaintext_256);
    }

    SECTION("rejects a tampered ciphertext byte") {
        auto broken = sealed_256;
        broken[0] ^= 0x01;
        REQUIRE_FALSE(pqvpn::tunnel_decrypt(
            std::span<const uint8_t>(broken), key_256, nonce_256,
            std::span<const uint8_t>(aad_256)));
    }

    SECTION("rejects a tampered authentication tag") {
        auto broken = sealed_256;
        broken.back() ^= 0x80;
        REQUIRE_FALSE(pqvpn::tunnel_decrypt(
            std::span<const uint8_t>(broken), key_256, nonce_256,
            std::span<const uint8_t>(aad_256)));
    }

    SECTION("rejects AAD that does not match the sealed frame header") {
        auto wrong_aad = aad_256;
        wrong_aad[1] ^= 0xff; // flip the frame type byte
        REQUIRE_FALSE(pqvpn::tunnel_decrypt(
            std::span<const uint8_t>(sealed_256), key_256, nonce_256,
            std::span<const uint8_t>(wrong_aad)));
    }

    SECTION("rejects payloads shorter than the authentication tag") {
        const std::vector<uint8_t> too_short{0x01, 0x02};
        REQUIRE_FALSE(pqvpn::tunnel_decrypt(
            std::span<const uint8_t>(too_short), key_256, nonce_256,
            std::span<const uint8_t>(aad_256)));
    }

    SECTION("rejects a key size that is neither AES-128 nor AES-256") {
        const std::vector<uint8_t> odd_key(20, 0x7f);
        REQUIRE_THROWS_AS(pqvpn::tunnel_encrypt(
            std::span<const uint8_t>(plaintext_256), odd_key, nonce_256,
            std::span<const uint8_t>(aad_256)), std::invalid_argument);
    }
}

TEST_CASE("tunnel_encrypt matches AES-128-GCM known-answer vectors", "[tunnel][aead][kat]") {
    const auto sealed = pqvpn::tunnel_encrypt(
        std::span<const uint8_t>(plaintext_128), key_128, nonce_128,
        std::span<const uint8_t>(aad_128));

    REQUIRE(sealed == sealed_128);

    SECTION("decrypts back to the original plaintext") {
        const auto opened = pqvpn::tunnel_decrypt(
            std::span<const uint8_t>(sealed_128), key_128, nonce_128,
            std::span<const uint8_t>(aad_128));
        REQUIRE(opened);
        REQUIRE(*opened == plaintext_128);
    }

    SECTION("rejects a tampered authentication tag") {
        auto broken = sealed_128;
        broken.back() ^= 0x40;
        REQUIRE_FALSE(pqvpn::tunnel_decrypt(
            std::span<const uint8_t>(broken), key_128, nonce_128,
            std::span<const uint8_t>(aad_128)));
    }

    SECTION("rejects AAD that does not match the sealed frame header") {
        auto wrong_aad = aad_128;
        wrong_aad[3] ^= 0x0f; // flip one next-hop hash byte
        REQUIRE_FALSE(pqvpn::tunnel_decrypt(
            std::span<const uint8_t>(sealed_128), key_128, nonce_128,
            std::span<const uint8_t>(wrong_aad)));
    }
}
