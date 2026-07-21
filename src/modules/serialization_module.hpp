#ifndef PQVPN_SERIALIZATION_HPP
#define PQVPN_SERIALIZATION_HPP

#include <string>
#include <vector>
#include <expected>
#include <nlohmann/json.hpp>
#include "config_module.hpp"

namespace pqvpn::serialization {

    /**
     * @brief Robust JSON serializer for the PQVPN configuration.
     *
     * Provides high-level serialization and deserialization using nlohmann::json,
     * with support for partial configuration updates during deserialization.
     */
    class JsonSerializer {
    public:
        /**
         * @brief Serializes a Config object to a JSON string.
         * @param cfg The configuration object to serialize.
         * @return A pretty-printed JSON string representing the config.
         */
        static std::string serialize(const config::Config& cfg) {
            nlohmann::json j = cfg;
            return j.dump(2); // 2-space indentation for readability
        }

        /**
         * @brief Deserializes a JSON string into a Config object.
         *
         * This method supports partial JSON strings by merging provided values
         * with the default configuration.
         *
         * @param json_str The JSON string to parse.
         * @return An expected containing the loaded Config or an error message string.
         */
        static std::expected<config::Config, std::string> deserialize(std::string_view json_str) {
            try {
                auto j = nlohmann::json::parse(json_str);
                config::Config cfg; // Start with default values from config_module.hpp

                if (j.contains("security")) {
                    const auto& s = j["security"];
                    if (s.contains("strict_sig_verify")) cfg.security.strict_sig_verify = s["strict_sig_verify"].get<bool>();
                    if (s.contains("tofu")) cfg.security.tofu = s["tofu"].get<bool>();
                    if (s.contains("known_peers_file")) cfg.security.known_peers_file = s["known_peers_file"].get<std::string>();
                    if (s.contains("allowlist") && s["allowlist"].is_array()) {
                        cfg.security.allowlist = s["allowlist"].get<std::vector<std::string>>();
                    }

                    if (s.contains("kdf")) {
                        const auto& k = s["kdf"];
                        if (k.contains("time_cost")) cfg.security.kdf.time_cost = k["time_cost"].get<int>();
                        if (k.contains("memory_cost_kib")) cfg.security.kdf.memory_cost_kib = k["memory_cost_kib"].get<int>();
                        if (k.contains("parallelism")) cfg.security.kdf.parallelism = k["parallelism"].get<int>();
                    }
                }

                if (j.contains("network")) {
                    const auto& n = j["network"];
                    if (n.contains("port")) cfg.network.port = n["port"].get<int>();
                    if (n.contains("bind_address")) cfg.network.bind_address = n["bind_address"].get<std::string>();
                }

                return cfg;
            } catch (const std::exception& e) {
                return std::unexpected(std::string("JSON Deserialization Error: ") + e.what());
            }
        }
    };

} // namespace pqvpn::serialization

#endif // PQVPN_SERIALIZATION_HPP
