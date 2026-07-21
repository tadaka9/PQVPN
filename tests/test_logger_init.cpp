#include <catch2/catch_test_macros.hpp>
#include "logging_module.hpp"
#include <filesystem>

TEST_CASE("setup_logger replaces handlers and creates a default file", "[logging][parity]") {
    using namespace pqvpn::logging;
    const auto path = std::filesystem::temp_directory_path() / "pqvpn_setup_logger_test.log";
    std::filesystem::remove(path);

    auto first = Logger::setup_logger("setup_logger_test", LogLevel::info, path.string());
    REQUIRE(first->sinks().size() == 2);
    REQUIRE(first->level() == spdlog::level::info);
    first->info("first");
    first->flush();
    REQUIRE(std::filesystem::exists(path));

    auto second = Logger::setup_logger("setup_logger_test", LogLevel::debug, path.string());
    REQUIRE(second != first);
    REQUIRE(second->sinks().size() == 2); // no duplicated handlers
    REQUIRE(second->level() == spdlog::level::debug);
    REQUIRE(spdlog::get("setup_logger_test") == second);
    second->debug("second");
    second->flush();

    spdlog::drop("setup_logger_test");
    first.reset();
    second.reset();
    std::filesystem::remove(path);
}

TEST_CASE("setup_logger survives file sink failure", "[logging][parity]") {
    using namespace pqvpn::logging;
    auto logger = Logger::setup_logger(
        "setup_logger_bad_file", LogLevel::warn,
        std::filesystem::temp_directory_path().string()); // directory cannot be opened as a file
    REQUIRE(logger->sinks().size() == 1);
    REQUIRE(logger->level() == spdlog::level::warn);
    REQUIRE_NOTHROW(logger->warn("console remains available"));
    spdlog::drop("setup_logger_bad_file");
}
