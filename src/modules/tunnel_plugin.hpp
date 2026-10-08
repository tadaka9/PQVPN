#pragma once

#include <filesystem>
#include <stdexcept>
#include <string>

namespace pqvpn::tunnel {

enum class Backend { Native, WireGuard, OpenVPN };

inline Backend backend_from_string(const std::string& value) {
    if (value == "pqvpn") return Backend::Native;
    if (value == "wireguard") return Backend::WireGuard;
    if (value == "openvpn") return Backend::OpenVPN;
    throw std::invalid_argument("unknown tunnel plugin: " + value);
}

// External plugins are deliberately constrained to a regular file path. The
// process supervisor will execute a fixed backend binary without a shell;
// this validator is shared by CLI, GUI and future dynamic plugin loading.
inline std::filesystem::path validate_config_path(Backend backend, const std::string& value) {
    if (backend == Backend::Native) return {};
    if (value.empty()) throw std::invalid_argument("external tunnel config path is empty");
    const std::filesystem::path path(value);
    if (!path.is_absolute() || path.filename() == "." || path.filename() == "..") {
        throw std::invalid_argument("external tunnel config path must be absolute");
    }
    return path;
}

} // namespace pqvpn::tunnel
