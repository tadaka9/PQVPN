#ifndef PQVPN_CONFIG_HPP
#define PQVPN_CONFIG_HPP

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <optional>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <string_view>

namespace pqvpn::config {
    struct KDFConfig {
        int time_cost = 3;
        int memory_cost_kib = 65536;
        int parallelism = 4;

        friend void from_json(const nlohmann::json& j, KDFConfig& value) {
            value.time_cost = j.value("time_cost", value.time_cost);
            value.memory_cost_kib = j.value("memory_cost_kib", value.memory_cost_kib);
            value.parallelism = j.value("parallelism", value.parallelism);
        }
        friend void to_json(nlohmann::json& j, const KDFConfig& value) {
            j = {{"time_cost", value.time_cost}, {"memory_cost_kib", value.memory_cost_kib}, {"parallelism", value.parallelism}};
        }
    };

    struct NetworkConfig {
        int port = 8080;
        std::string bind_address = "0.0.0.0";

        friend void from_json(const nlohmann::json& j, NetworkConfig& value) {
            value.port = j.value("port", value.port);
            value.bind_address = j.value("bind_address", value.bind_address);
        }
        friend void to_json(nlohmann::json& j, const NetworkConfig& value) {
            j = {{"port", value.port}, {"bind_address", value.bind_address}};
        }
    };

    struct SecurityConfig {
        bool strict_sig_verify = false;
        bool tofu = true;
        std::vector<std::string> allowlist;
        std::string known_peers_file = "known_peers.yaml";
        std::optional<std::string> known_peers_passphrase;
        KDFConfig kdf;

        friend void from_json(const nlohmann::json& j, SecurityConfig& value) {
            value.strict_sig_verify = j.value("strict_sig_verify", value.strict_sig_verify);
            value.tofu = j.value("tofu", value.tofu);
            value.allowlist = j.value("allowlist", value.allowlist);
            value.known_peers_file = j.value("known_peers_file", value.known_peers_file);
            if (j.contains("known_peers_passphrase") && j.at("known_peers_passphrase").is_string())
                value.known_peers_passphrase = j.at("known_peers_passphrase").get<std::string>();
            if (j.contains("kdf")) value.kdf = j.at("kdf").get<KDFConfig>();
        }
        friend void to_json(nlohmann::json& j, const SecurityConfig& value) {
            j = {{"strict_sig_verify", value.strict_sig_verify}, {"tofu", value.tofu},
                 {"allowlist", value.allowlist}, {"known_peers_file", value.known_peers_file}, {"kdf", value.kdf}};
            if (value.known_peers_passphrase) j["known_peers_passphrase"] = *value.known_peers_passphrase;
        }
    };

    struct Config {
        SecurityConfig security;
        NetworkConfig network;

        friend void from_json(const nlohmann::json& j, Config& value) {
            if (j.contains("security")) value.security = j.at("security").get<SecurityConfig>();
            if (j.contains("network")) value.network = j.at("network").get<NetworkConfig>();
        }
        friend void to_json(nlohmann::json& j, const Config& value) {
            j = {{"security", value.security}, {"network", value.network}};
        }
    };

    struct ConfigError {
        std::string message;
    };

    inline std::optional<ConfigError> validate_config(const Config& cfg) {
        if (cfg.network.port <= 0 || cfg.network.port > 65535) {
            return ConfigError{"Invalid network port: " + std::to_string(cfg.network.port)};
        }
        if (cfg.network.bind_address.empty()) {
            return ConfigError{"Bind address cannot be empty"};
        }
        if (cfg.security.kdf.time_cost <= 0) {
            return ConfigError{"KDF time_cost must be positive"};
        }
        if (cfg.security.kdf.memory_cost_kib <= 0) {
            return ConfigError{"KDF memory_cost_kib must be positive"};
        }
        return std::nullopt;
    }

    inline std::optional<Config> load_config(std::string_view path) {
        if (path.empty()) {
            return std::nullopt;
        }

        std::ifstream file((std::string(path)));
        if (!file.is_open()) {
            return std::nullopt;
        }

        try {
            nlohmann::json j;
            file >> j;

            Config cfg = j.get<Config>();

            auto validation_error = validate_config(cfg);
            if (validation_error) {
                return std::nullopt; // In a real system we'd return error, but keeping signature simple
            }

            return cfg;
        } catch (const std::exception& e) {
            return std::nullopt;
        }
    }
} // namespace pqvpn::config

#endif // PQVPN_CONFIG_HPP