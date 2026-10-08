#pragma once

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#include "tunnel_plugin.hpp"

namespace pqvpn::tunnel {

// Fixed executable mapping shared by all frontends. The supervisor must pass
// argv directly to the OS process API; it must never invoke a shell.
struct ExternalProcessSpec {
    Backend backend = Backend::Native;
    std::filesystem::path config;
    std::chrono::milliseconds startup_timeout{10000};

    std::vector<std::string> argv() const {
        if (backend == Backend::WireGuard) {
            return {"wg-quick", "up", config.string()};
        }
        if (backend == Backend::OpenVPN) {
            return {"openvpn", "--config", config.string()};
        }
        throw std::invalid_argument("native backend has no external process");
    }
};

inline ExternalProcessSpec make_external_process_spec(Backend backend,
                                                       const std::string& config) {
    ExternalProcessSpec spec{backend, validate_config_path(backend, config)};
    if (spec.config.empty()) {
        throw std::invalid_argument("external plugin configuration is required");
    }
    return spec;
}

} // namespace pqvpn::tunnel
