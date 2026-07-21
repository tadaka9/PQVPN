#include <catch2/catch_test_macros.hpp>
#include "crypto_signature.hpp"
#include "crypto_utils.hpp"

TEST_CASE("ML-DSA-87 signature round trip", "[crypto][signature][verify]") {
    const auto keys = pqvpn::pq_sig_keygen();
    const std::vector<uint8_t> message{'P', 'Q', 'V', 'P', 'N'};
    const auto signature = pqvpn::pq_sig_sign(keys.secret_key, message);

    REQUIRE(pqvpn::pq_sig_verify(keys.public_key, message, signature));

    auto changed = message;
    changed.back() ^= 1;
    REQUIRE_FALSE(pqvpn::pq_sig_verify(keys.public_key, changed, signature));
}

TEST_CASE("ML-DSA-87 verification rejects malformed input", "[crypto][signature][verify]") {
    REQUIRE_FALSE(pqvpn::pq_sig_verify({}, {1}, {}));
    REQUIRE_FALSE(pqvpn::pq_sig_verify({1, 2, 3}, {1}, {4, 5, 6}));
}
