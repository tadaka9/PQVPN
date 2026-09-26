#include "windows_adapter.hpp"

#ifdef _WIN32

namespace pqvpn::platform {

bool WindowsTapAdapter::open(InboundHandler inbound) {
    if (!inbound) return false;
    try {
        tap_.open(requested_guid_, std::move(inbound));
        return tap_.is_open();
    } catch (const std::exception&) {
        // Device setup failed: report through the interface contract instead
        // of unwinding the caller. The node decides fail-closed vs UDP-only.
        return false;
    }
}

bool WindowsTapAdapter::write(const Packet& packet) noexcept {
    try {
        return tap_.write(packet);
    } catch (const std::exception&) {
        return false;
    }
}

void WindowsTapAdapter::close() noexcept {
    // WindowsTap::close is idempotent.
    tap_.close();
}

std::string WindowsTapAdapter::describe() const {
    const auto& guid = tap_.guid().empty() ? requested_guid_ : tap_.guid();
    return "Windows TAP adapter" + (guid.empty() ? std::string(" (auto-detect)") : " " + guid);
}

std::unique_ptr<Adapter> make_adapter(std::string_view device_hint) {
    // Convention: "own" or a \\.\ device path selects PQVPN's own NDIS driver.
    // Everything else falls back to TAP-Windows (transitional backend).
    if (device_hint == "own" ||
        (device_hint.size() >= 4 && device_hint.substr(0, 4) == "\\\\.")) {
        return std::unique_ptr<Adapter>(new WindowsOwnTunnel(std::string(device_hint)));
    }
    return std::unique_ptr<Adapter>(new WindowsTapAdapter(std::string(device_hint)));
}

} // namespace pqvpn::platform

#endif // _WIN32
