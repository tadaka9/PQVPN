#include <catch2/catch_test_macros.hpp>
#include "serialization_module.hpp"
#include "config_module.hpp"
#include <string>

namespace pqvpn::test {

TEST_CASE("JsonSerializer Round-trip", "[serialization]") {
    config::Config original;
    original.network.port = 8080;
    original.network.bind_address = "127.0.0.1";
    original.security.strict_sig_verify = true;
    original.security.tofu = false;
    original.security.known_peers_file = "/etc/pqvpn/peers";
    original.security.allowlist = {"192.168.1.1", "10.0.0.1"};
    original.security.kdf.time_cost = 500;
    original.security.kdf.memory_cost_kib = 1024;
    original.security.kdf.parallelism = 4;

    std::string json_str = serialization::JsonSerializer::serialize(original);
    auto result = serialization::JsonSerializer::deserialize(json_str);

    REQUIRE(result.has_value());
    const auto& deserialized = result.value();

    CHECK(deserialized.network.port == original.network.port);
    CHECK(deserialized.network.bind_address == original.network.bind_address);
    CHECK(deserialized.security.strict_sig_verify == original.security.strict_sig_verify);
    CHECK(deserialized.security.tofu == original.security.tofu);
    CHECK(deserialized.security.known_peers_file == original.security.known_peers_file);
    CHECK(deserialized.security.allowlist == original.security.allowlist);
    CHECK(deserialized.security.kdf.time_cost == original.security.kdf.time_cost);
    CHECK(deserialized.security.kdf.memory_cost_kib == original.security.kdf.memory_cost_kib);
    CHECK(deserialized.security.kdf.parallelism == original.security.kdf.parallelism);
}

TEST_CASE("JsonSerializer Malformed JSON", "[serialization]") {
    std::string malformed_json = "{ \"network\": { \"port\": 8080 "; // Missing closing braces

    auto result = serialization::JsonSerializer::deserialize(malformed_json);

    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("JsonSerializer Partial JSON", "[serialization]") {
    // Test that missing fields use defaults from the default-constructed Config
    std::string partial_json = R"({
        "network": { "port": 9000 }
    })";

    auto result = serialization::JsonSerializer::deserialize(partial_json);

    REQUIRE(result.has_value());
    const auto& deserialized = result.value();

    CHECK(deserialized.network.port == 9000);
}

} // namespace pqvpn::test
