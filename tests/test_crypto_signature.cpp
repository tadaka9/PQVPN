#include <catch2/catch_test_macros.hpp>
#include "crypto_utils.hpp"

TEST_CASE("ML-DSA-87 signing produces a signature", "[crypto][signature]") {
    const auto keys = pqvpn::pq_sig_keygen();
    const std::vector<uint8_t> message{'P', 'Q', 'V', 'P', 'N'};
    const auto signature = pqvpn::pq_sig_sign(keys.secret_key, message);
    REQUIRE_FALSE(signature.empty());
}

TEST_CASE("ML-DSA-87 signing rejects malformed keys", "[crypto][signature]") {
    REQUIRE_THROWS_AS(pqvpn::pq_sig_sign({1, 2, 3}, {4, 5, 6}), std::invalid_argument);
}
