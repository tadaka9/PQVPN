#include <catch2/catch_test_macros.hpp>
#include "hybrid_auth.hpp"

TEST_CASE("hybrid authentication requires Ed25519 and ML-DSA-87", "[crypto][hybrid][auth]") {
    const auto ed25519 = pqvpn::crypto::ed25519_keygen();
    const auto ml_dsa = pqvpn::pq_sig_keygen();
    const std::vector<uint8_t> transcript{'P', 'Q', 'V', 'P', 'N', '-', 'H', 'S', '1'};
    const auto signature = pqvpn::crypto::sign_hybrid_transcript(
        transcript, ed25519.private_key, ml_dsa.secret_key);

    REQUIRE(pqvpn::crypto::verify_hybrid_transcript(
        transcript, ed25519.public_key, ml_dsa.public_key, signature));

    auto damaged_ed25519 = signature;
    damaged_ed25519.ed25519[0] ^= 1;
    REQUIRE_FALSE(pqvpn::crypto::verify_hybrid_transcript(
        transcript, ed25519.public_key, ml_dsa.public_key, damaged_ed25519));

    auto damaged_ml_dsa = signature;
    damaged_ml_dsa.ml_dsa_87[0] ^= 1;
    REQUIRE_FALSE(pqvpn::crypto::verify_hybrid_transcript(
        transcript, ed25519.public_key, ml_dsa.public_key, damaged_ml_dsa));

    auto changed_transcript = transcript;
    changed_transcript.back() ^= 1;
    REQUIRE_FALSE(pqvpn::crypto::verify_hybrid_transcript(
        changed_transcript, ed25519.public_key, ml_dsa.public_key, signature));
}
