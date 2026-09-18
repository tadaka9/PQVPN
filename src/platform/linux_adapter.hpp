#pragma once

#ifdef __linux__

#include <string>

#include "adapter.hpp"
#include "linux_tun.hpp"

namespace pqvpn::platform {

// Adapter implementation backed by a Linux layer-3 TUN device (/dev/net/tun,
// IFF_TUN | IFF_NO_PI). Address, route and DNS configuration remain the job
// of a privileged network manager; this class only owns the packet boundary.
class LinuxTunAdapter final : public Adapter {
public:
    // requested_name may be empty (kernel-selected) or an IFNAMSIZ-safe name.
    explicit LinuxTunAdapter(std::string requested_name = {})
        : requested_name_(std::move(requested_name)) {}

    bool open(InboundHandler inbound) override;
    [[nodiscard]] bool write(const Packet& packet) noexcept override;
    void close() noexcept override;

    [[nodiscard]] bool is_open() const noexcept override { return tun_.is_open(); }
    [[nodiscard]] std::string describe() const override;

private:
    std::string requested_name_;
    LinuxTun tun_;
};

} // namespace pqvpn::platform

#endif // __linux__
