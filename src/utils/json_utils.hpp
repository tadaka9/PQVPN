#ifndef PQVPN_JSON_UTILS_HPP
#define PQVPN_JSON_UTILS_HPP

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>
#include <cstdint>

namespace pqvpn::utils {

/**
 * @brief Return canonical bytes for signing/verifying, mirroring Python's
 * json.dumps(..., separators=(",", ":"), sort_keys=...) behavior.
 *
 * @param obj The JSON object to serialize.
 * @param field_order Optional list of keys to include in the output in a specific order.
 * @return std::vector<uint8_t> The canonical byte representation.
 */
inline std::vector<uint8_t> canonical_sign_bytes(
    const nlohmann::json& obj,
    const std::optional<std::vector<std::string>>& field_order = std::nullopt
) {
    try {
        if (field_order.has_value()) {
            // Case 1: Explicit order provided.
            // We MUST use ordered_json to preserve the insertion order.
            nlohmann::ordered_json output_json = nlohmann::ordered_json::object();
            for (const auto& key : *field_order) {
                if (obj.contains(key)) {
                    output_json[key] = obj[key];
                }
            }
            // dump() without indent results in no spaces between separators by default
            std::string s = output_json.dump();
            return std::vector<uint8_t>(s.begin(), s.end());
        } else {
            // Case 2: Default sorted keys behavior.
            // nlohmann::json objects are inherently sorted by key.
            std::string s = obj.dump();
            return std::vector<uint8_t>(s.begin(), s.end());
        }
    } catch (const std::exception& e) {
        try {
            std::string s = obj.dump();
            return std::vector<uint8_t>(s.begin(), s.end());
        } catch (...) {
            return {};
        }
    }
}

} // namespace pqvpn::utils

#endif // PQVPN_JSON_UTILS_HPP
