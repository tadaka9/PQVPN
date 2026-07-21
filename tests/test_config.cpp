#include <catch2/catch_test_macros.hpp>
#include "../src/modules/config_module.hpp"
#include <fstream>
#include <cstdio>
#include <filesystem>

static std::string temp_config_path(const char* name) {
    return (std::filesystem::temp_directory_path() / name).string();
}

TEST_CASE("Config loading valid", "[config]") {
    // Use a path relative to the project root so it works regardless of execution dir
    const std::string config_path = temp_config_path("pqvpn_test_config_valid.json");
    {
        std::ofstream ofs(config_path);
        ofs << R"({
            "security": {
                "strict_sig_verify": true,
                "kdf": {
                    "time_cost": 5,
                    "memory_cost_kib": 131072
                }
            },
            "network": {
                "port": 9090,
                "bind_address": "127.0.0.1"
            }
        })";
    }

    auto result = pqvpn::config::load_config(config_path);
    REQUIRE(result.has_value());
    const auto& cfg = result.value();
    CHECK(cfg.network.port == 9090);
    CHECK(cfg.network.bind_address == "127.0.0.1");
    CHECK(cfg.security.kdf.time_cost == 5);

    std::remove(config_path.c_str());
}

TEST_CASE("Config loading invalid port", "[config]") {
    const std::string config_path = temp_config_path("pqvpn_test_config_invalid_port.json");
    {
        std::ofstream ofs(config_path);
        ofs << R"({
            "network": {
                "port": -1
            }
        })";
    }

    auto result = pqvpn::config::load_config(config_path);
    REQUIRE_FALSE(result.has_value());
    std::remove(config_path.c_str());
}

TEST_CASE("Config loading file not found", "[config]") {
    auto result = pqvpn::config::load_config("tests/non_existent_file.json");
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("Config loading malformed JSON", "[config]") {
    const std::string config_path = temp_config_path("pqvpn_test_config_malformed.json");
    {
        std::ofstream ofs_real(config_path);
        ofs_real << R"({ \"network\": { \"port\": 8080 )";
    }

    auto result = pqvpn::config::load_config(config_path);
    REQUIRE_FALSE(result.has_value());
    std::remove(config_path.c_str());
}

TEST_CASE("Config validation kdf zero", "[config]") {
    const std::string config_path = temp_config_path("pqvpn_test_config_kdf_zero.json");
    {
        std::ofstream ofs(config_path);
        ofs << R"({
            \"security\": {
                \"kdf\": {
                    \"time_cost\": 0
                }
            }
        })";
    }

    auto result = pqvpn::config::load_config(config_path);
    REQUIRE_FALSE(result.has_value());
    std::remove(config_path.c_str());
}
