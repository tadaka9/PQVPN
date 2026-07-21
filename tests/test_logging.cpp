#include <catch2/catch_test_macros.hpp>
#include "../src/modules/logging_module.hpp"
#include <string>

TEST_CASE("Logger basic logging", "[logging]") {
    try {
        pqvpn::logging::Logger::info("Testing basic info log with argument: {}", 42);
        pqvpn::logging::Logger::warn("Testing warning log: {}", "string content");
        pqvpn::logging::Logger::error("Error level check.");
    } catch (const std::exception& e) {
        FAIL("Logger threw an exception: " + std::string(e.what()));
    }
}

TEST_CASE("Logger format errors", "[logging]") {
    try {
        pqvpn::logging::Logger::info("Unmatched argument: {}", 1);
    } catch (...) {
        FAIL("Logger allowed a format exception to escape!");
    }
}
