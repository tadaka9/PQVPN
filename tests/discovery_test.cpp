#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include "discovery_module.hpp"
#include "dht_module.hpp"
#include "node_module.hpp"

TEST_CASE("Discovery basic initialization", "[discovery]") {
    auto node = std::make_shared<pqvpn::PQVPNNode>("test_config.yaml");
    pqvpn::discovery::Discovery::Config config;
    config.enabled = true;
    pqvpn::discovery::Discovery discovery(node, config);
    REQUIRE(config.enabled == true);
}
