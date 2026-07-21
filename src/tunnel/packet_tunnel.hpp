#ifndef PQVPN_PACKET_TUNNEL_HPP
#define PQVPN_PACKET_TUNNEL_HPP

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace pqvpn::tunnel {

enum class PacketLayer {
    network,
    ethernet,
};

class PacketTunnel {
public:
    using Packet = std::vector<std::uint8_t>;
    using PacketHandler = std::function<void(Packet)>;
    using ErrorHandler = std::function<void(std::string)>;

    virtual ~PacketTunnel() = default;

    PacketTunnel(const PacketTunnel&) = delete;
    PacketTunnel& operator=(const PacketTunnel&) = delete;

    virtual void start(PacketHandler packet_handler, ErrorHandler error_handler) = 0;
    virtual void write(std::span<const std::uint8_t> packet) = 0;
    virtual void stop() noexcept = 0;
    [[nodiscard]] virtual bool is_running() const noexcept = 0;
    [[nodiscard]] virtual PacketLayer layer() const noexcept = 0;
    [[nodiscard]] virtual std::string name() const = 0;

protected:
    PacketTunnel() = default;
};

} // namespace pqvpn::tunnel

#endif
