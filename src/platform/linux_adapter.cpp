#include "linux_adapter.hpp"

#ifdef __linux__

namespace pqvpn::platform {

bool LinuxTunAdapter::open(InboundHandler inbound) {
    if (!inbound) return false;
    try {
        tun_.open(requested_name_, std::move(inbound));
        return tun_.is_open();
    } catch (const std::exception&) {
        // No /dev/net/tun access, name clash, or missing CAP_NET_ADMIN:
        // report through the interface contract instead of unwinding.
        return false;
    }
}

bool LinuxTunAdapter::write(const Packet& packet) noexcept {
    return tun_.write_packet(packet);
}

void LinuxTunAdapter::close() noexcept {
    // LinuxTun::close is idempotent.
    tun_.close();
}

std::string LinuxTunAdapter::describe() const {
    if (tun_.is_open()) return "Linux TUN interface " + tun_.name();
    return requested_name_.empty()
        ? std::string("Linux TUN interface (kernel-selected)")
        : "Linux TUN interface " + requested_name_;
}

std::unique_ptr<Adapter> make_adapter(std::string_view device_hint) {
    return std::unique_ptr<Adapter>(new LinuxTunAdapter(std::string(device_hint)));
}

} // namespace pqvpn::platform

#endif // __linux__
