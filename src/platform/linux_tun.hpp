#pragma once

#ifdef __linux__

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace pqvpn::platform {

// Owns a Linux layer-3 TUN device. Address, route and DNS configuration are
// deliberately left to a privileged, transactional network manager.
class LinuxTun final {
public:
    using PacketHandler = std::function<void(std::vector<std::uint8_t>)>;
    using ErrorHandler = std::function<void(std::string)>;

    static constexpr std::size_t max_packet_size = 65'535;

    LinuxTun() = default;
    ~LinuxTun();

    LinuxTun(const LinuxTun&) = delete;
    LinuxTun& operator=(const LinuxTun&) = delete;

    // requested_name may be empty (kernel-selected) or an IFNAMSIZ-safe name.
    // Throws std::system_error/std::invalid_argument on setup failure.
    void open(std::string requested_name, PacketHandler packets,
              ErrorHandler errors = {});
    void close() noexcept;

    // Returns false for a closed device, malformed IP packet, or failed write.
    [[nodiscard]] bool write_packet(const std::vector<std::uint8_t>& packet) noexcept;

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] std::string name() const;

    // Checks that a buffer contains one bounded IPv4 or IPv6 packet. Padding is
    // accepted because some producers expose a buffer larger than the IP length.
    [[nodiscard]] static bool valid_ip_packet(const std::uint8_t* data,
                                               std::size_t size) noexcept;

private:
    void read_loop() noexcept;
    void report_error(std::string message) noexcept;

    mutable std::mutex mutex_;
    int device_fd_ = -1;
    int cancel_fd_ = -1;
    std::string name_;
    PacketHandler packet_handler_;
    ErrorHandler error_handler_;
    std::thread reader_;
    std::atomic_bool stopping_{false};
};

} // namespace pqvpn::platform

#endif // __linux__
