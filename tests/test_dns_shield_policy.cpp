#include <catch2/catch_test_macros.hpp>
#include "dns_shield_policy.hpp"
#include "local_dns_filter.hpp"

TEST_CASE("DNS Shield accepts one canonical policy set", "[shield]") {
    for (const auto profile : pqvpn::shield::profiles)
        CHECK(pqvpn::shield::valid_profile(profile));
    CHECK_FALSE(pqvpn::shield::valid_profile("default"));
    CHECK_FALSE(pqvpn::shield::valid_profile("OFF"));
    CHECK(pqvpn::shield::valid_profile("custom"));
    CHECK(pqvpn::shield::exit_profile("custom") == "off");
    CHECK(pqvpn::shield::exit_profile("privacy") == "privacy");
}

TEST_CASE("custom DNS rules remain local and match subdomains", "[shield]") {
    pqvpn::shield::LocalDnsFilter filter;
    filter.load({}, {"tracker.example", "||ads.example^", "*.metrics.example"});
    CHECK(filter.size() == 3);
    CHECK(filter.blocks("tracker.example"));
    CHECK(filter.blocks("img.TRACKER.example."));
    CHECK(filter.blocks("cdn.ads.example"));
    CHECK(filter.blocks("metrics.example"));
    CHECK_FALSE(filter.blocks("example"));
    CHECK_FALSE(filter.blocks("nottracker.example.net"));

    std::vector<std::uint8_t> query(40, 0);
    query[0] = 0x45; query[9] = 17; query[20] = 0xcf; query[21] = 0x08;
    query[22] = 0; query[23] = 53; query[32] = 0; query[33] = 1;
    query.push_back(7); query.insert(query.end(), {'t','r','a','c','k','e','r'});
    query.push_back(7); query.insert(query.end(), {'e','x','a','m','p','l','e'}); query.push_back(0);
    query.insert(query.end(), {0, 1, 0, 1});
    const auto response = filter.filter_packet(query);
    REQUIRE_FALSE(response.empty());
    CHECK(response[20] == 0);
    CHECK(response[21] == 53);
    CHECK((response[30] & 0x80) != 0);
    CHECK((response[31] & 0x0f) == 3);
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
