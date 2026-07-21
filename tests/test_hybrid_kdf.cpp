#include <catch2/catch_test_macros.hpp>
#include "hybrid_kdf.hpp"

TEST_CASE("hybrid KDF binds both secrets and the transcript", "[crypto][hybrid][sha3]") {
    const std::vector<uint8_t> classical_secret(32, 0x11);
    const std::vector<uint8_t> post_quantum_secret(32, 0x22);
    const std::vector<uint8_t> transcript{'P', 'Q', 'V', 'P', 'N'};

    const auto first = pqvpn::crypto::combine_hybrid_secrets(
        classical_secret, post_quantum_secret, transcript);
    const auto repeated = pqvpn::crypto::combine_hybrid_secrets(
        classical_secret, post_quantum_secret, transcript);
    REQUIRE(first.size() == 32);
    REQUIRE(first == repeated);

    auto changed_post_quantum = post_quantum_secret;
    changed_post_quantum[0] ^= 1;
    REQUIRE(first != pqvpn::crypto::combine_hybrid_secrets(
        classical_secret, changed_post_quantum, transcript));

    auto changed_transcript = transcript;
    changed_transcript.back() ^= 1;
    REQUIRE(first != pqvpn::crypto::combine_hybrid_secrets(
        classical_secret, post_quantum_secret, changed_transcript));
}

TEST_CASE("hybrid KDF fails closed when a component is absent", "[crypto][hybrid][sha3]") {
    REQUIRE_THROWS_AS(pqvpn::crypto::combine_hybrid_secrets({}, {1}, {2}), std::invalid_argument);
    REQUIRE_THROWS_AS(pqvpn::crypto::combine_hybrid_secrets(std::vector<uint8_t>(32), {}, {2}), std::invalid_argument);
    REQUIRE_THROWS_AS(pqvpn::crypto::combine_hybrid_secrets(std::vector<uint8_t>(32), {1}, {}), std::invalid_argument);
}
