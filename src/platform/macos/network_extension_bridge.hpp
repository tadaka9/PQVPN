#pragma once

#ifdef __APPLE__

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace pqvpn::platform::macos {

// Boundary between the portable PQVPN core and an Apple Network Extension.
// The Objective-C++ NEPacketTunnelProvider host owns NEPacketTunnelFlow and
// supplies these callbacks. This class does not create an extension, request
// entitlements, install routes, or bypass Apple's signing/provisioning model.
class NetworkExtensionBridge final {
public:
    using Packet = std::vector<std::uint8_t>;
    using CorePacketHandler = std::function<void(Packet)>;
    using PacketFlowWriter = std::function<bool(const Packet&)>;
    using ErrorHandler = std::function<void(std::string)>;

    void attach(CorePacketHandler from_packet_flow,
                PacketFlowWriter to_packet_flow,
                ErrorHandler errors = {});
    void detach() noexcept;

    // Called by the NEPacketTunnelProvider after it reads an IPv4/IPv6 packet.
    [[nodiscard]] bool receive_from_packet_flow(Packet packet) noexcept;
    // Called by the PQVPN core after authenticated decryption.
    [[nodiscard]] bool write_to_packet_flow(const Packet& packet) noexcept;

    [[nodiscard]] bool attached() const noexcept;

private:
    static bool valid_ip_packet(const Packet& packet) noexcept;
    void error(std::string message) noexcept;

    CorePacketHandler core_reader_;
    PacketFlowWriter flow_writer_;
    ErrorHandler error_handler_;
};

} // namespace pqvpn::platform::macos

#endif // __APPLE__
