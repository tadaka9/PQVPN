#include <catch2/catch_test_macros.hpp>
#include "crypto_utils.hpp"

TEST_CASE("ML-DSA-87 key generation uses liboqs", "[crypto][signature]") {
    const auto first = pqvpn::pq_sig_keygen();
    const auto second = pqvpn::pq_sig_keygen(std::string("ML-DSA-87"));

    REQUIRE_FALSE(first.public_key.empty());
    REQUIRE_FALSE(first.secret_key.empty());
    REQUIRE(first.public_key != second.public_key);
    REQUIRE(first.secret_key != second.secret_key);
}

TEST_CASE("unsupported signature algorithms are rejected", "[crypto][signature]") {
    REQUIRE_THROWS_AS(pqvpn::pq_sig_keygen(std::string("unsupported")), std::invalid_argument);
}
