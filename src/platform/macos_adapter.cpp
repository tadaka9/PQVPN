#include "macos_adapter.hpp"

#ifdef __APPLE__

namespace pqvpn::platform {

bool NetworkExtensionAdapter::open(InboundHandler inbound) {
    if (!inbound) return false;
    inbound_ = std::move(inbound);
    // No flow writer yet: writes drop fail-closed until attach_extension()
    // plugs in the NEPacketTunnelProvider's real packet flow.
    bridge_.attach([this](macos::NetworkExtensionBridge::Packet packet) {
        if (inbound_) inbound_(std::move(packet));
    },
    [](const macos::NetworkExtensionBridge::Packet&) -> bool { return false; });
    return bridge_.attached();
}

bool NetworkExtensionAdapter::write(const Packet& packet) noexcept {
    return bridge_.write_to_packet_flow(packet);
}

void NetworkExtensionAdapter::close() noexcept {
    // NetworkExtensionBridge::detach is idempotent.
    bridge_.detach();
    inbound_ = {};
}

std::string NetworkExtensionAdapter::describe() const {
    return "macOS Network Extension boundary" + (bridge_.attached() ? std::string(" (attached)") : std::string(" (no packet flow attached)"));
}

void NetworkExtensionAdapter::attach_extension(PacketFlowWriter writer) {
    if (!writer || !inbound_) return;
    bridge_.attach([this](macos::NetworkExtensionBridge::Packet packet) {
        if (inbound_) inbound_(std::move(packet));
    }, std::move(writer));
}

bool NetworkExtensionAdapter::receive_from_packet_flow(Packet packet) noexcept {
    return bridge_.receive_from_packet_flow(std::move(packet));
}

std::unique_ptr<Adapter> make_adapter(std::string_view /*device_hint*/) {
    return std::unique_ptr<Adapter>(new NetworkExtensionAdapter);
}

} // namespace pqvpn::platform

#endif // __APPLE__
