#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include "discovery_module.hpp"
#include "node_module.hpp"

using json = nlohmann::json;

TEST_CASE("Discovery build_record complete implementation", "[discovery][build_record]") {
    // Test that we can at least create a Discovery instance and call build_record
    asio::io_context io_context;
    auto node = std::make_shared<pqvpn::PQVPNNode>(io_context, "test_config.yaml");

    pqvpn::discovery::Discovery::Config config;
    config.publish_addr = true;
    config.ttl = 1800;
    config.seq = 42;
    config.relay = false;

    pqvpn::discovery::Discovery discovery(node, config);

    // Call the build_record method and check it compiles
    auto [key, record] = discovery.build_record();

    // Basic checks - the key should start with expected prefix
    REQUIRE(key.substr(0, 12) == "pqvpn:peer:");

    // Check required fields exist in record
    REQUIRE(record.contains("peerid"));
    REQUIRE(record.contains("nickname"));
    REQUIRE(record.contains("addr"));
    REQUIRE(record.contains("ed25519_pk"));
    REQUIRE(record.contains("brainpoolP512r1_pk"));
    REQUIRE(record.contains("kyber_pk"));
    REQUIRE(record.contains("mldsa_pk"));
    REQUIRE(record.contains("ts"));
    REQUIRE(record.contains("ttl"));
    REQUIRE(record.contains("seq"));
    REQUIRE(record.contains("relay"));

    // Check basic values
    REQUIRE(record["peerid"].get<std::string>().empty() == true);  // No my_id set yet
    REQUIRE(record["nickname"].get<std::string>() == "");
    REQUIRE(record["addr"].get<std::string>() == "");
    REQUIRE(record["ed25519_pk"].get<std::string>() == "");
    REQUIRE(record["brainpoolP512r1_pk"].get<std::string>() == "");
    REQUIRE(record["kyber_pk"].get<std::string>() == "");
    REQUIRE(record["mldsa_pk"].get<std::string>() == "");

    // Check numeric values
    REQUIRE(record["ts"].get<uint64_t>() > 0);
    REQUIRE(record["ttl"].get<uint64_t>() == 1800);
    REQUIRE(record["seq"].get<int>() == 42);
    REQUIRE(record["relay"].get<bool>() == false);
}
