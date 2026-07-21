#include <catch2/catch_test_macros.hpp>
#include "network_module.hpp"
#include "config_module.hpp"

TEST_CASE("UDPListener basic functionality", "[network]") {
    pqvpn::config::NetworkConfig config;
    config.port = 12345;
    config.bind_address = "127.0.0.1";

    pqvpn::network::UDPListener listener(config);

    SECTION("Initial state: not running") {
        REQUIRE_FALSE(listener.is_running());
    }

    SECTION("Start succeeds with valid config") {
        auto result = listener.start();
        REQUIRE(result.has_value());
        REQUIRE(listener.is_running());
    }

    SECTION("Stop works correctly") {
        listener.start();
        listener.stop();
        REQUIRE_FALSE(listener.is_running());
    }

    SECTION("Start fails with invalid port") {
        config.port = 0; // Invalid port based on our validation logic
        pqvpn::network::UDPListener bad_listener(config);
        auto result = bad_listener.start();
        REQUIRE_FALSE(result.has_value());
        REQUIRE(result.error() == pqvpn::network::NetworkError::AddressInvalid);
    }
}
