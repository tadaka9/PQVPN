#include "network_extension_bridge.hpp"

#ifdef __APPLE__

#include <utility>

namespace pqvpn::platform::macos {

void NetworkExtensionBridge::attach(CorePacketHandler from_packet_flow,
                                    PacketFlowWriter to_packet_flow,
                                    ErrorHandler errors) {
    core_reader_ = std::move(from_packet_flow);
    flow_writer_ = std::move(to_packet_flow);
    error_handler_ = std::move(errors);
}

void NetworkExtensionBridge::detach() noexcept {
    core_reader_ = {};
    flow_writer_ = {};
    error_handler_ = {};
}

bool NetworkExtensionBridge::receive_from_packet_flow(Packet packet) noexcept {
    if (!core_reader_ || !valid_ip_packet(packet)) return false;
    try {
        core_reader_(std::move(packet));
        return !packet.empty();
    } catch (...) {
        error("PQVPN core rejected a packet from NEPacketTunnelFlow");
        return false;
    }
}

bool NetworkExtensionBridge::write_to_packet_flow(const Packet& packet) noexcept {
    if (!flow_writer_ || !valid_ip_packet(packet)) return false;
    try {
        return flow_writer_(packet);
    } catch (...) {
        error("NEPacketTunnelFlow writer failed");
        return false;
    }
}

bool NetworkExtensionBridge::attached() const noexcept {
    return static_cast<bool>(core_reader_) && static_cast<bool>(flow_writer_);
}

bool NetworkExtensionBridge::valid_ip_packet(const Packet& packet) noexcept {
    if (packet.empty() || packet.size() > 65'535) return false;
    const unsigned version = packet.front() >> 4;
    if (version == 4) {
        if (packet.size() < 20) return false;
        const std::size_t header = (packet[0] & 0x0fU) * 4U;
        const std::size_t total = (static_cast<std::size_t>(packet[2]) << 8U) | packet[3];
        return header >= 20 && total >= header && total <= packet.size();
    }
    if (version == 6) {
        if (packet.size() < 40) return false;
        const std::size_t payload = (static_cast<std::size_t>(packet[4]) << 8U) | packet[5];
        return 40U + payload <= packet.size();
    }
    return false;
}

void NetworkExtensionBridge::error(std::string message) noexcept {
    if (!error_handler_) return;
    try { error_handler_(std::move(message)); } catch (...) {}
}

} // namespace pqvpn::platform::macos

#endif // __APPLE__
