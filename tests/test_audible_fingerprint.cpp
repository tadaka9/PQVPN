#include <catch2/catch_test_macros.hpp>

#include "modules/audible_fingerprint.hpp"

TEST_CASE("audible fingerprint is stable and identity-specific", "[wallet][audio]") {
    const auto first = pqvpn::audible::from_public_identity("pqc1-example-public-identity");
    const auto again = pqvpn::audible::from_public_identity("pqc1-example-public-identity");
    const auto other = pqvpn::audible::from_public_identity("pqc1-different-public-identity");
    CHECK(first.midi == again.midi);
    CHECK(first.midi != other.midi);
    CHECK_FALSE(first.notation().empty());
}

TEST_CASE("audible fingerprint synthesis is short and bounded", "[wallet][audio]") {
    const auto melody = pqvpn::audible::from_public_identity("pqc1-example-public-identity");
    const auto pcm = pqvpn::audible::synthesize(melody, 16000, 115, 0.18);
    CHECK(pcm.size() == 8U * 1840U);
    REQUIRE_FALSE(pcm.empty());
    const auto peak = *std::max_element(pcm.begin(), pcm.end());
    CHECK(peak < 8192);
}
