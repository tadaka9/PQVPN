#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pqvpn::shield {

inline constexpr std::array<std::string_view, 6> profiles{
    "off", "dnscrypt", "privacy", "security", "family", "maximum"};

inline bool valid_profile(std::string_view value) noexcept {
    for (const auto profile : profiles) if (profile == value) return true;
    return false;
}

// Stable CGNAT address derived from the authenticated 256-bit peer identity.
// 100.64.0.0/10 is not routed on the public Internet. Reserved service/gateway
// values are skipped. The exit recomputes this value and never trusts a
// client-supplied address.
inline std::optional<std::string> internal_ipv4(const std::vector<std::uint8_t>& peer_id) {
    if (peer_id.size() < 3) return std::nullopt;
    std::uint32_t host = (static_cast<std::uint32_t>(peer_id[0]) << 14) |
                         (static_cast<std::uint32_t>(peer_id[1]) << 6) |
                         (static_cast<std::uint32_t>(peer_id[2]) >> 2);
    host = (host % ((1u << 22) - 2u)) + 2u;
    const std::uint32_t address = 0x64400000u | host;
    return std::to_string((address >> 24) & 0xff) + "." +
           std::to_string((address >> 16) & 0xff) + "." +
           std::to_string((address >> 8) & 0xff) + "." +
           std::to_string(address & 0xff);
}

inline constexpr std::string_view dns_service_ipv4 = "100.64.0.1";

} // namespace pqvpn::shield
