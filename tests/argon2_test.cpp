#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <string>
#include <cstring>
#include "modules/crypto_module.hpp"

TEST_CASE("Argon2 key derivation with valid inputs", "[argon2]") {
    std::string password = "my_password";
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    size_t key_length = 32;

    auto result = pqvpn::crypto::argon2_derive_key_material(password, salt, key_length);

    REQUIRE(result.size() == key_length);
}

TEST_CASE("Argon2 key derivation with default salt", "[argon2]") {
    std::string password = "test_password";
    size_t key_length = 16;

    REQUIRE_THROWS_AS(pqvpn::crypto::argon2_derive_key_material(password, {}, key_length), std::invalid_argument);
}

TEST_CASE("Argon2 key derivation with empty password", "[argon2]") {
    std::string password = "";
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    size_t key_length = 24;

    auto result = pqvpn::crypto::argon2_derive_key_material(password, salt, key_length);

    REQUIRE(result.size() == key_length);
}

TEST_CASE("Argon2 key derivation with custom parameters", "[argon2]") {
    std::string password = "custom_params_test";
    std::vector<uint8_t> salt = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    size_t key_length = 48;

    auto result = pqvpn::crypto::argon2_derive_key_material(password, salt, key_length, 4, (1 << 17), 2);

    REQUIRE(result.size() == key_length);
}
