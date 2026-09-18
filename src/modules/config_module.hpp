#ifndef PQVPN_CONFIG_HPP
#define PQVPN_CONFIG_HPP

#include <iostream>
#include <sstream>
#include <stdexcept>
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

    // A bootstrap peer the node actively contacts at startup (and until a
    // session with it is established): either "host:port" or {"host","port"}.
    struct BootstrapPeer {
        std::string host;
        int port = 0;

        friend void from_json(const nlohmann::json& j, BootstrapPeer& value) {
            if (j.is_string()) {
                const auto text = j.get<std::string>();
                const auto pos = text.rfind(':');
                if (pos == std::string::npos || pos == 0 || pos + 1 >= text.size()) {
                    throw std::runtime_error("bootstrap entry must be host:port");
                }
                value.host = text.substr(0, pos);
                value.port = std::stoi(text.substr(pos + 1));
            } else if (j.is_object()) {
                value.host = j.value("host", std::string{});
                value.port = j.value("port", 0);
            } else {
                throw std::runtime_error("bootstrap entry must be a string or object");
            }
        }
        friend void to_json(nlohmann::json& j, const BootstrapPeer& value) {
            j = {{"host", value.host}, {"port", value.port}};
        }
    };

    // Optional runtime tuning. Every field is optional; an omitted (or null)
    // field keeps the node's built-in protocol default, so existing configs
    // behave exactly as before. Present values must be positive.
    struct TuningConfig {
        std::optional<double> session_timeout_seconds;
        std::optional<double> keepalive_interval_seconds;
        std::optional<double> liveness_window_seconds;
        std::optional<double> handshake_timeout_seconds;
        std::optional<int> replay_window_size;
        std::optional<double> bootstrap_retry_seconds;

        friend void from_json(const nlohmann::json& j, TuningConfig& value) {
            auto opt_double = [](const nlohmann::json& obj, const char* key) -> std::optional<double> {
                if (obj.contains(key) && !obj.at(key).is_null() && obj.at(key).is_number()) {
                    return obj.at(key).get<double>();
                }
                return std::nullopt;
            };
            value.session_timeout_seconds = opt_double(j, "session_timeout_seconds");
            value.keepalive_interval_seconds = opt_double(j, "keepalive_interval_seconds");
            value.liveness_window_seconds = opt_double(j, "liveness_window_seconds");
            value.handshake_timeout_seconds = opt_double(j, "handshake_timeout_seconds");
            if (j.contains("replay_window_size") && !j.at("replay_window_size").is_null() &&
                j.at("replay_window_size").is_number_integer()) {
                value.replay_window_size = j.at("replay_window_size").get<int>();
            }
            value.bootstrap_retry_seconds = opt_double(j, "bootstrap_retry_seconds");
        }
        friend void to_json(nlohmann::json& j, const TuningConfig& value) {
            auto put_opt = [&j](const char* key, const std::optional<double>& v) {
                if (v.has_value()) j[key] = *v;
            };
            put_opt("session_timeout_seconds", value.session_timeout_seconds);
            put_opt("keepalive_interval_seconds", value.keepalive_interval_seconds);
            put_opt("liveness_window_seconds", value.liveness_window_seconds);
            put_opt("handshake_timeout_seconds", value.handshake_timeout_seconds);
            if (value.replay_window_size.has_value()) j["replay_window_size"] = *value.replay_window_size;
            put_opt("bootstrap_retry_seconds", value.bootstrap_retry_seconds);
        }
    };

    // Tunnel device selection. interface_name is platform-specific: a TUN
    // name on Linux (empty = kernel-selected) or a TAP GUID on Windows
    // (empty = auto-detect). CLI flags still take precedence where they exist.
    struct TunnelConfig {
        std::string interface_name;

        friend void from_json(const nlohmann::json& j, TunnelConfig& value) {
            if (j.contains("interface_name") && j.at("interface_name").is_string()) {
                value.interface_name = j.at("interface_name").get<std::string>();
            }
        }
        friend void to_json(nlohmann::json& j, const TunnelConfig& value) {
            j = {{"interface_name", value.interface_name}};
        }
    };

    struct Config {
        SecurityConfig security;
        NetworkConfig network;
        std::vector<BootstrapPeer> bootstrap;
        TuningConfig tuning;
        TunnelConfig tunnel;

        friend void from_json(const nlohmann::json& j, Config& value) {
            if (j.contains("security")) value.security = j.at("security").get<SecurityConfig>();
            if (j.contains("network")) value.network = j.at("network").get<NetworkConfig>();
            if (j.contains("bootstrap") && j.at("bootstrap").is_array()) {
                for (const auto& entry : j.at("bootstrap")) {
                    value.bootstrap.push_back(entry.get<BootstrapPeer>());
                }
            }
            if (j.contains("tuning")) value.tuning = j.at("tuning").get<TuningConfig>();
            if (j.contains("tunnel")) value.tunnel = j.at("tunnel").get<TunnelConfig>();
        }
        friend void to_json(nlohmann::json& j, const Config& value) {
            j = {{"security", value.security}, {"network", value.network}, {"bootstrap", value.bootstrap}};
            if (value.tuning.session_timeout_seconds || value.tuning.keepalive_interval_seconds ||
                value.tuning.liveness_window_seconds || value.tuning.handshake_timeout_seconds ||
                value.tuning.replay_window_size || value.tuning.bootstrap_retry_seconds) {
                j["tuning"] = value.tuning;
            }
            if (!value.tunnel.interface_name.empty()) j["tunnel"] = value.tunnel;
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
        // Tuning overrides are validated below; omitted fields keep defaults.
        const auto tuning_positive = [](const std::optional<double>& value, const char* name) -> bool {
            (void)name;
            return !value.has_value() || *value > 0.0;
        };
        if (!tuning_positive(cfg.tuning.session_timeout_seconds, "session_timeout_seconds")) {
            return ConfigError{"tuning.session_timeout_seconds must be positive"};
        }
        if (!tuning_positive(cfg.tuning.keepalive_interval_seconds, "keepalive_interval_seconds")) {
            return ConfigError{"tuning.keepalive_interval_seconds must be positive"};
        }
        if (!tuning_positive(cfg.tuning.liveness_window_seconds, "liveness_window_seconds")) {
            return ConfigError{"tuning.liveness_window_seconds must be positive"};
        }
        if (!tuning_positive(cfg.tuning.handshake_timeout_seconds, "handshake_timeout_seconds")) {
            return ConfigError{"tuning.handshake_timeout_seconds must be positive"};
        }
        if (!tuning_positive(cfg.tuning.bootstrap_retry_seconds, "bootstrap_retry_seconds")) {
            return ConfigError{"tuning.bootstrap_retry_seconds must be positive"};
        }
        if (cfg.tuning.replay_window_size.has_value() && *cfg.tuning.replay_window_size < 2) {
            return ConfigError{"tuning.replay_window_size must be at least 2"};
        }
        // A liveness window that reaches the prune horizon would make every
        // session both "silent" and unprunable — reject the combination.
        if (cfg.tuning.liveness_window_seconds && cfg.tuning.session_timeout_seconds &&
            *cfg.tuning.liveness_window_seconds >= *cfg.tuning.session_timeout_seconds) {
            return ConfigError{"tuning.liveness_window_seconds must be smaller than tuning.session_timeout_seconds"};
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