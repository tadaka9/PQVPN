#include <catch2/catch_test_macros.hpp>
#include "../src/modules/logging_module.hpp"
#include <string>

TEST_CASE("Logging level to string", "[logging]") {
    REQUIRE(pqvpn::logging::to_string(pqvpn::logging::LogLevel::trace) == "trace");
    REQUIRE(pqvpn::logging::to_string(pqvpn::logging::LogLevel::debug) == "debug");
    REQUIRE(pqvpn::logging::to_string(pqvpn::logging::LogLevel::info)  == "info");
    REQUIRE(pqvpn::logging::to_string(pqvpn::logging::LogLevel::warn) == "warn");
    REQUIRE(pqvpn::logging::to_string(pqvpn::logging::LogLevel::error) == "error");
    REQUIRE(pqvpn::logging::to_string(pqvpn::logging::LogLevel::critical) == "critical");
}

TEST_CASE("Logging format no crash", "[logging]") {
    CHECK_NOTHROW(pqvpn::logging::Logger::info("Testing format with integer: {}", 42));
    CHECK_NOTHROW(pqvpn::logging::Logger::error("Testing format with string: {}", "test_string"));
    CHECK_NOTHROW(pqvpn::logging::Logger::warn("Testing multiple args: {} and {}", 1.23, 456));
}
