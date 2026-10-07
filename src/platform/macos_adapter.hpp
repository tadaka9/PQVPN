#pragma once

#ifdef __APPLE__

#include <functional>
#include <string>

#include "adapter.hpp"
#include "macos/network_extension_bridge.hpp"

namespace pqvpn::platform {

// Adapter implementation backed by the Apple Network Extension boundary. On
// macOS the NEPacketTunnelProvider host (a separate, signed extension) owns
// the packet flow; this adapter exposes that boundary through the uniform
// interface. Until an extension attaches a real flow writer, core-to-device
// writes are dropped fail-closed and the node runs UDP-only.
class NetworkExtensionAdapter final : public Adapter {
public:
    using PacketFlowWriter = std::function<bool(const Packet&)>;

    bool open(InboundHandler inbound) override;
    [[nodiscard]] bool write(const Packet& packet) noexcept override;
    void close() noexcept override;

    [[nodiscard]] bool is_open() const noexcept override { return bridge_.attached(); }
    [[nodiscard]] std::string describe() const override;

    // Called by the NEPacketTunnelProvider host once it owns a live
    // NEPacketTunnelFlow. Re-attaches the stored inbound handler with the
    // real writer so core packets reach the extension.
    void attach_extension(PacketFlowWriter writer);

    // Called by the NEPacketTunnelProvider host when its packet flow delivers
    // an IPv4/IPv6 packet into the core.
    [[nodiscard]] bool receive_from_packet_flow(Packet packet) noexcept;


private:
    macos::NetworkExtensionBridge bridge_;
    InboundHandler inbound_;
};

} // namespace pqvpn::platform

#endif // __APPLE__
