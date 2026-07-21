#include <catch2/catch_test_macros.hpp>
#include "crypto_module.hpp"

TEST_CASE("X25519 derives the same shared secret on both sides", "[crypto][x25519]") {
    const auto alice = pqvpn::crypto::X25519::keygen();
    const auto bob = pqvpn::crypto::X25519::keygen();

    REQUIRE(alice.public_key.size() == 32);
    REQUIRE(alice.private_key.size() == 32);
    REQUIRE(bob.public_key != alice.public_key);

    const auto alice_secret = pqvpn::crypto::X25519::derive(alice.private_key, bob.public_key);
    const auto bob_secret = pqvpn::crypto::X25519::derive(bob.private_key, alice.public_key);
    REQUIRE(alice_secret.size() == 32);
    REQUIRE(alice_secret == bob_secret);
}

TEST_CASE("X25519 rejects malformed key material", "[crypto][x25519]") {
    REQUIRE_THROWS_AS(pqvpn::crypto::X25519::derive({1, 2}, std::vector<uint8_t>(32)), std::invalid_argument);
}
