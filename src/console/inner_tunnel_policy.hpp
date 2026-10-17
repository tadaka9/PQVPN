#pragma once

#include <optional>
#include <string>
#include "config_module.hpp"

namespace pqvpn::console {

struct InnerTunnelOverride {
    std::optional<std::string> backend;
    std::optional<std::string> config_path;
    bool disable = false;
};

inline const char* inner_tunnel_label(const config::InnerTunnelConfig& value) {
    if (!value.enabled) return "Off";
    return value.backend == "wireguard" ? "WireGuard inside PQVPN" : "OpenVPN inside PQVPN";
}

// One canonical override operation is shared by the node CLI and TUI.  It is
// a pure assignment: applying the same request repeatedly yields the same
// configuration and never starts a process by itself.
inline std::optional<std::string> apply_inner_tunnel_override(
    config::Config& value, const InnerTunnelOverride& request) {
    if (request.disable) {
        value.inner_tunnel = {};
    } else if (request.backend || request.config_path) {
        if (request.backend) value.inner_tunnel.backend = *request.backend;
        if (request.config_path) value.inner_tunnel.config_path = *request.config_path;
        value.inner_tunnel.enabled = true;
    }
    if (const auto error = config::validate_config(value)) return error->message;
    return std::nullopt;
}

inline bool parse_inner_tunnel_argument(const std::string& argument,
                                        const std::string& following,
                                        InnerTunnelOverride& request) {
    if (argument == "--inner-tunnel-backend") {
        if (following != "wireguard" && following != "openvpn") return false;
        request.backend = following;
        return true;
    }
    if (argument == "--inner-tunnel-config") {
        if (following.empty()) return false;
        request.config_path = following;
        return true;
    }
    return false;
}

} // namespace pqvpn::console
