#include <catch2/catch_test_macros.hpp>
#include "../src/modules/logging_module.hpp"
#include <string>
#include <cstdlib>
#include <regex>

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
        // spdlog/fmt usually handles this or throws depending on configuration,
        // but our Logger class has a try-catch block.
        pqvpn::logging::Logger::info("Unmatched argument: {}", 1);
    } catch (...) {
        FAIL("Logger allowed a format exception to escape!");
    }
}

TEST_CASE("Logger IPv4 Redaction", "[logging]") {
    std::string msg = "Connection from 192.168.1.1 established";

    SECTION("Redaction enabled") {
        #ifdef _WIN32
        _putenv("PQVPN_REDACT=1");
        #else
        setenv("PQVPN_REDACT", "1", 1);
        #endif

        std::string redacted = pqvpn::logging::Logger::redact_ipv4(msg);
        REQUIRE(redacted == "Connection from ***.***.***.*** established");
    }

    SECTION("Redaction disabled") {
        #ifdef _WIN32
        _putenv("PQVPN_REDACT=0");
        #else
        setenv("PQVPN_REDACT", "0", 1);
        #endif

        const auto formatted = pqvpn::logging::ColoredFormatter::format("INFO", msg);
        REQUIRE(formatted.find(msg) != std::string::npos);
    }
}

TEST_CASE("ColoredFormatter preserves Python format semantics", "[logging][parity]") {
#ifdef _WIN32
    _putenv("PQVPN_REDACT=0");
#else
    setenv("PQVPN_REDACT", "0", 1);
#endif
    const auto output = pqvpn::logging::ColoredFormatter::format(
        "INFO", "peer 192.168.1.1 connected");
    REQUIRE(std::regex_match(output, std::regex(
        "\\x1b\\[32m[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3} INFO {4} peer 192\\.168\\.1\\.1 connected\\x1b\\[0m")));

#ifdef _WIN32
    _putenv("PQVPN_REDACT=1");
#else
    setenv("PQVPN_REDACT", "1", 1);
#endif
    const auto redacted = pqvpn::logging::ColoredFormatter::format(
        "WARNING", "peer 999.999.999.999 connected");
    REQUIRE(redacted.find("\033[33m") == 0);
    REQUIRE(redacted.find("WARNING ") != std::string::npos);
    REQUIRE(redacted.find("***.***.***.***") != std::string::npos);
    REQUIRE(redacted.ends_with("\033[0m"));
}
