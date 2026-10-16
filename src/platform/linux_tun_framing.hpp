#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace pqvpn::platform {

// Linux IFF_TUN carries layer-3 IP packets while PQVPN's exit contract uses
// Ethernet-II frames. These conversions keep that wire contract explicit.
inline std::optional<std::vector<std::uint8_t>> tun_packet_to_ethernet(
    std::span<const std::uint8_t> packet) {
    if (packet.empty()) return std::nullopt;
    const auto version = packet.front() >> 4;
    const std::uint16_t ethertype = version == 4 ? 0x0800 : version == 6 ? 0x86DD : 0;
    if (ethertype == 0) return std::nullopt;
    constexpr std::array<std::uint8_t, 6> exit_mac{0x02, 0x9c, 0x4a, 0x7b, 0x3d, 0xe5};
    constexpr std::array<std::uint8_t, 6> client_mac{0x02, 0x70, 0x71, 0x76, 0x70, 0x6e};
    std::vector<std::uint8_t> frame;
    frame.reserve(14 + packet.size());
    frame.insert(frame.end(), exit_mac.begin(), exit_mac.end());
    frame.insert(frame.end(), client_mac.begin(), client_mac.end());
    frame.push_back(static_cast<std::uint8_t>(ethertype >> 8));
    frame.push_back(static_cast<std::uint8_t>(ethertype));
    frame.insert(frame.end(), packet.begin(), packet.end());
    return frame;
}

inline std::optional<std::vector<std::uint8_t>> ethernet_to_tun_packet(
    std::span<const std::uint8_t> frame) {
    if (frame.size() < 15) return std::nullopt;
    const auto ethertype = static_cast<std::uint16_t>((frame[12] << 8) | frame[13]);
    const auto expected_version = ethertype == 0x0800 ? 4 : ethertype == 0x86DD ? 6 : 0;
    if (expected_version == 0 || (frame[14] >> 4) != expected_version) return std::nullopt;
    return std::vector<std::uint8_t>(frame.begin() + 14, frame.end());
}

} // namespace pqvpn::platform
