#pragma once

#ifdef _WIN32

#include <string>

#include "adapter.hpp"
#include "windows_tap.hpp"

namespace pqvpn::platform {

// Adapter implementation backed by a TAP-Windows device. Route installation
// stays in the node runtime; this class only owns the device I/O boundary and
// exposes the underlying WindowsTap for OS-specific work (e.g. finding the
// adapter's IPv4 address before installing routes).
class WindowsTapAdapter final : public Adapter {
public:
    explicit WindowsTapAdapter(std::string requested_guid = {})
        : requested_guid_(std::move(requested_guid)) {}

    bool open(InboundHandler inbound) override;
    [[nodiscard]] bool write(const Packet& packet) noexcept override;
    void close() noexcept override;

    [[nodiscard]] bool is_open() const noexcept override { return tap_.is_open(); }
    [[nodiscard]] std::string describe() const override;

    // The owned device, for Windows-specific work (route installation).
    WindowsTap& device() noexcept { return tap_; }

private:
    std::string requested_guid_;
    WindowsTap tap_;
};

} // namespace pqvpn::platform

#endif // _WIN32
