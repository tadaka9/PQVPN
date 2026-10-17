#pragma once

#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "config_module.hpp"

namespace pqvpn::console {

struct TrafficShapingOverride {
    std::optional<bool> enabled;
    std::optional<traffic::ShapingMode> mode;
    std::optional<std::size_t> max_padding_bytes;
    std::optional<int> max_delay_ms;
};

inline bool parse_shaping_argument(std::string_view option, std::string_view value,
                                   TrafficShapingOverride& result) {
    if (option == "--shaping") {
        if (value == "on") result.enabled = true;
        else if (value == "off") result.enabled = false;
        else return false;
        return true;
    }
    if (option == "--shaping-mode") {
        const auto mode = traffic::shaping_mode_from_string(value);
        if (!mode) return false;
        result.mode = *mode;
        return true;
    }
    if (option == "--shaping-padding") {
        std::size_t parsed = 0;
        const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
        if (error != std::errc{} || end != value.data() + value.size() || parsed > 4096) return false;
        result.max_padding_bytes = parsed;
        return true;
    }
    if (option == "--shaping-delay") {
        int parsed = 0;
        const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
        if (error != std::errc{} || end != value.data() + value.size() || parsed < 0 || parsed > 100) return false;
        result.max_delay_ms = parsed;
        return true;
    }
    return false;
}

inline void apply_traffic_shaping_override(config::Config& config,
                                           const TrafficShapingOverride& value) {
    if (value.enabled) config.traffic_shaping.enabled = *value.enabled;
    if (value.mode) config.traffic_shaping.mode = *value.mode;
    if (value.max_padding_bytes) config.traffic_shaping.max_padding_bytes = *value.max_padding_bytes;
    if (value.max_delay_ms) config.traffic_shaping.max_delay_ms = *value.max_delay_ms;
}

inline std::string shaping_label(const traffic::ShapingConfig& value) {
    if (!value.enabled) return "Off";
    return std::string{traffic::to_string(value.mode)} + " / " +
        std::to_string(value.max_padding_bytes) + " B / " +
        std::to_string(value.max_delay_ms) + " ms";
}

inline void append_traffic_shaping_arguments(std::vector<std::string>& arguments,
                                             const traffic::ShapingConfig& value) {
    arguments.insert(arguments.end(), {"--shaping", value.enabled ? "on" : "off",
        "--shaping-mode", traffic::to_string(value.mode),
        "--shaping-padding", std::to_string(value.max_padding_bytes),
        "--shaping-delay", std::to_string(value.max_delay_ms)});
}

} // namespace pqvpn::console
