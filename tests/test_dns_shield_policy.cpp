#include <catch2/catch_test_macros.hpp>
#include "dns_shield_policy.hpp"

TEST_CASE("DNS Shield accepts one canonical policy set", "[shield]") {
    for (const auto profile : pqvpn::shield::profiles)
        CHECK(pqvpn::shield::valid_profile(profile));
    CHECK_FALSE(pqvpn::shield::valid_profile("default"));
    CHECK_FALSE(pqvpn::shield::valid_profile("OFF"));
}

TEST_CASE("authenticated peer identity maps deterministically into CGNAT", "[shield]") {
    std::vector<std::uint8_t> peer(32, 0x42);
    const auto first = pqvpn::shield::internal_ipv4(peer);
    const auto second = pqvpn::shield::internal_ipv4(peer);
    REQUIRE(first);
    CHECK(first == second);
    CHECK(first->rfind("100.", 0) == 0);
    peer[0] ^= 0xff;
    CHECK(pqvpn::shield::internal_ipv4(peer) != first);
    CHECK_FALSE(pqvpn::shield::internal_ipv4({1, 2}));
}
