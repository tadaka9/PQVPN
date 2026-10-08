#pragma once

#ifdef _WIN32

#include <windows.h>

#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <cstdint>

#include "adapter.hpp"

namespace pqvpn::platform {

// Adapter implementation backed by PQVPN's own NDIS tunnel driver.
// Communicates with the kernel via \\.\PQVPN_TUN0 using CreateFile/ReadFile/WriteFile.
// The kernel owns the bounded queue; this reader delivers one IP datagram at a time.
class WindowsOwnTunnel final : public Adapter {
public:
    explicit WindowsOwnTunnel(std::string device_name = {})
        : device_name_(std::move(device_name)) {}

    ~WindowsOwnTunnel() override;

    bool open(InboundHandler inbound) override;
    [[nodiscard]] bool write(const Packet& packet) noexcept override;
    void close() noexcept override;

    [[nodiscard]] bool is_open() const noexcept override;
    [[nodiscard]] std::string describe() const override;

private:
    void receive_loop();

    std::string device_name_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::atomic<bool> open_{false};
    std::atomic<bool> stopping_{false};
    InboundHandler inbound_handler_;
    std::thread receiver_thread_;
    std::mutex write_mutex_;

};

} // namespace pqvpn::platform

#endif // _WIN32
