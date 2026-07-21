#include <catch2/catch_test_macros.hpp>
#include "load_balancer.hpp"
#include <vector>
#include <cstdint>
#include <unordered_map>

struct TestBytesHasher {
    std::size_t operator()(const pqvpn::Bytes& v) const {
        std::size_t seed = 0;
        for(auto x : v) {
            seed ^= std::hash<uint8_t>{}(x)
                 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }
};

TEST_CASE("LoadBalancer initialization", "[load_balancer]") {
    pqvpn::LoadBalancer lb;

    SECTION("Default rate limit is applied for unknown peer") {
        std::vector<uint8_t> peer_id = {0xDE, 0xAD, 0xBE, 0xEF};
        REQUIRE(lb.get_rate_limit(peer_id) == pqvpn::DEFAULT_PPS_LIMIT);
    }

    SECTION("Explicit rate limit can be set") {
        std::vector<uint8_t> peer_id = {0xDE, 0xAD, 0xBE, 0xEF};
        lb.set_rate_limit(peer_id, 500);
        REQUIRE(lb.get_rate_limit(peer_id) == 500);
    }
}

TEST_CASE("LoadBalancer select_session", "[load_balancer]") {
    pqvpn::LoadBalancer lb;
    using Hasher = TestBytesHasher;
    std::unordered_map<pqvpn::Bytes, pqvpn::SessionInfo, Hasher> sessions;

    pqvpn::Bytes s1 = {0x01};
    pqvpn::Bytes s2 = {0x02};
    pqvpn::Bytes s3 = {0x03};

    SECTION("Empty sessions returns nullopt") {
        REQUIRE(lb.select_session(sessions) == std::nullopt);
    }

    SECTION("Only established sessions are considered") {
        sessions[s1] = {pqvpn::SessionState::HANDSHAKING, 0};
        sessions[s2] = {pqvpn::SessionState::ESTABLISHED, 500};
        sessions[s3] = {pqvpn::SessionState::CLOSING, 0};

        auto result = lb.select_session(sessions);
        REQUIRE(result.has_value());
        REQUIRE(*result == s2);
    }

    SECTION("Selects session with lowest bytes_sent (highest score)") {
        sessions[s1] = {pqvpn::SessionState::ESTABLISHED, 800}; // score 0.2
        sessions[s2] = {pqvpn::SessionState::ESTABLISHED, 200}; // score 0.8
        sessions[s3] = {pqvpn::SessionState::ESTABLISHED, 500}; // score 0.5

        auto result = lb.select_session(sessions);
        REQUIRE(result.has_value());
        REQUIRE(*result == s2);
    }

    SECTION("Returns nullopt if no sessions are established") {
        sessions[s1] = {pqvpn::SessionState::HANDSHAKING, 0};
        sessions[s3] = {pqvpn::SessionState::CLOSING, 0};
        REQUIRE(lb.select_session(sessions) == std::nullopt);
    }
}
