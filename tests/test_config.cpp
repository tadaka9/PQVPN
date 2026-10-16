#include <catch2/catch_test_macros.hpp>
#include "../src/modules/config_module.hpp"
#include <algorithm>
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
    CHECK_FALSE(cfg.tunnel.enabled);

    std::remove(config_path.c_str());
}

TEST_CASE("Relay-only and full-tunnel profiles validate before startup", "[config][tunnel]") {
    pqvpn::config::Config relay;
    CHECK_FALSE(relay.tunnel.enabled);
    CHECK_FALSE(pqvpn::config::validate_config(relay).has_value());

    pqvpn::config::Config incomplete;
    incomplete.tunnel.enabled = true;
    auto missing = pqvpn::config::validate_config(incomplete);
    REQUIRE(missing.has_value());
    CHECK(missing->message.find("interface_name") != std::string::npos);

    incomplete.tunnel.interface_name = "pqvpn0";
    missing = pqvpn::config::validate_config(incomplete);
    REQUIRE(missing.has_value());
    CHECK(missing->message.find("exit_host") != std::string::npos);

    pqvpn::config::Config client;
    client.tunnel.enabled = true;
    client.tunnel.interface_name = "pqvpn0";
    client.tunnel.exit_host = "45.248.37.87";
    client.tunnel.exit_port = 9090;
    CHECK_FALSE(pqvpn::config::validate_config(client).has_value());

    const std::string incomplete_path = temp_config_path("pqvpn_test_incomplete_tunnel.json");
    {
        std::ofstream output(incomplete_path);
        output << R"({"network":{"port":9090},"tunnel":{}})";
    }
    CHECK_FALSE(pqvpn::config::load_config(incomplete_path).has_value());
    std::remove(incomplete_path.c_str());
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

TEST_CASE("Config loads adaptive UDP TCP policy", "[config][transport]") {
    const std::string config_path = temp_config_path("pqvpn_test_config_adaptive.json");
    {
        std::ofstream ofs(config_path);
        ofs << R"({
            "network": {"port": 9090},
            "adaptive_transport": {
                "enabled": true,
                "mode": "auto",
                "loss_switch_percent": 8.5,
                "jitter_switch_ms": 30.0,
                "failure_switch_count": 2,
                "recovery_probe_count": 5,
                "minimum_dwell_ms": 2500
            }
        })";
    }

    auto result = pqvpn::config::load_config(config_path);
    REQUIRE(result.has_value());
    CHECK(result->adaptive_transport.enabled);
    CHECK(result->adaptive_transport.mode == pqvpn::transport::Mode::Auto);
    CHECK(result->adaptive_transport.loss_switch_percent == 8.5);
    CHECK(result->adaptive_transport.failure_switch_count == 2);
    std::remove(config_path.c_str());
}

TEST_CASE("Config rejects invalid adaptive policy", "[config][transport]") {
    const std::string config_path = temp_config_path("pqvpn_test_config_adaptive_invalid.json");
    {
        std::ofstream ofs(config_path);
        ofs << R"({
            "network": {"port": 9090},
            "adaptive_transport": {"enabled": true, "mode": "sctp"}
        })";
    }

    CHECK_FALSE(pqvpn::config::load_config(config_path).has_value());
    std::remove(config_path.c_str());
}

TEST_CASE("Normalized configuration preserves an external backend without interface name", "[config][transport]") {
    for(const std::string backend:{"wireguard","openvpn"}) {
        pqvpn::config::Config original;
        original.tunnel.enabled=true;
        original.tunnel.plugin=backend;
        original.tunnel.config_path="/operator/client.conf";
        const nlohmann::json normalized=original;
        REQUIRE(normalized.contains("tunnel"));
        CHECK(normalized.at("tunnel").at("plugin")==backend);
        const auto restored=normalized.get<pqvpn::config::Config>();
        CHECK(restored.tunnel.plugin==backend);
        CHECK(restored.tunnel.enabled);
        CHECK(restored.tunnel.config_path==original.tunnel.config_path);
    }
}

TEST_CASE("Shipped config is the editable experimental mainnet profile", "[config][mainnet]") {
    const auto source_root=std::filesystem::path(__FILE__).parent_path().parent_path();
    const auto config_path=source_root/"config.json";
    const auto registry_path=source_root/"site/mainnet/peers.json";
    const auto profile=pqvpn::config::load_config(config_path.string());
    REQUIRE(profile.has_value());
    CHECK(profile->security.strict_sig_verify);
    CHECK(profile->security.tofu);
    CHECK(profile->security.known_peers_file=="known_peers.json");
    REQUIRE_FALSE(profile->bootstrap.empty());
    CHECK(profile->tunnel.enabled);
    CHECK(profile->tunnel.interface_name=="pqvpn0");
    CHECK(profile->tunnel.exit_host=="45.248.37.87");
    CHECK(profile->tunnel.exit_port==9090);

    std::ifstream registry_file(registry_path);
    REQUIRE(registry_file.good());
    const auto registry=nlohmann::json::parse(registry_file);
    CHECK(registry.at("network")=="pqvpn-mainnet-alpha");
    const auto endpoint=profile->bootstrap.front().host+":"+std::to_string(profile->bootstrap.front().port);
    const auto& peers=registry.at("peers");
    const auto published=std::find_if(peers.begin(),peers.end(),[&](const auto& peer){
        return peer.value("endpoint",std::string{})==endpoint &&
               std::find(peer.at("roles").begin(),peer.at("roles").end(),"bootstrap")!=peer.at("roles").end();
    });
    CHECK(published!=peers.end());
    const auto exit_endpoint=profile->tunnel.exit_host+":"+std::to_string(profile->tunnel.exit_port);
    const auto published_exit=std::find_if(peers.begin(),peers.end(),[&](const auto& peer){
        return peer.value("endpoint",std::string{})==exit_endpoint &&
               std::find(peer.at("roles").begin(),peer.at("roles").end(),"egress")!=peer.at("roles").end();
    });
    CHECK(published_exit!=peers.end());
}
