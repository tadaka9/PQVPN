#include <catch2/catch_test_macros.hpp>
#include "network_module.hpp"
#include "config_module.hpp"
#include <asio.hpp>

TEST_CASE("UDPListener basic functionality", "[network]") {
    // Reserve an ephemeral port so concurrent suites (including the
    // hard-kernel gate's nested CTest run) can never collide on a fixed one.
    asio::io_context io;
    asio::ip::udp::socket reservation(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));

    pqvpn::config::NetworkConfig config;
    config.port = static_cast<uint16_t>(reservation.local_endpoint().port());
    reservation.close();
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
