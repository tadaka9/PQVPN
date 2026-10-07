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
// Phase 2: bounded packet queues, backpressure, teardown drain.
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
    void drain_queues();

    std::string device_name_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::atomic<bool> open_{false};
    std::atomic<bool> stopping_{false};
    InboundHandler inbound_handler_;
    std::thread receiver_thread_;
    std::mutex write_mutex_;

    // Bounded receive queue (kernel -> user)
    static constexpr size_t kQueueCapacity = 1024;
    Packet receive_queue_[kQueueCapacity];
    std::atomic<size_t> queue_head_{0};
    std::atomic<size_t> queue_tail_{0};
    std::atomic<size_t> queue_size_{0};

    // Backpressure: block writes when queue is full
    bool enqueue_packet(std::vector<uint8_t>&& packet);
    std::vector<uint8_t> dequeue_packet();
};

} // namespace pqvpn::platform

#endif // _WIN32