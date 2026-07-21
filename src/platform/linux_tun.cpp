#include "linux_tun.hpp"

#ifdef __linux__

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <stdexcept>
#include <system_error>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace pqvpn::platform {
namespace {

std::system_error system_failure(const char* operation) {
    return std::system_error(errno, std::generic_category(), operation);
}

} // namespace

LinuxTun::~LinuxTun() { close(); }

void LinuxTun::open(std::string requested_name, PacketHandler packets,
                    ErrorHandler errors) {
    if (!packets) throw std::invalid_argument("LinuxTun requires a packet handler");
    if (requested_name.size() >= IFNAMSIZ) {
        throw std::invalid_argument("Linux TUN name exceeds IFNAMSIZ");
    }

    std::scoped_lock lock(mutex_);
    if (device_fd_ >= 0) throw std::logic_error("Linux TUN is already open");

    const int device = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (device < 0) throw system_failure("open /dev/net/tun");

    ifreq request{};
    request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
    if (!requested_name.empty()) {
        std::memcpy(request.ifr_name, requested_name.data(), requested_name.size());
        request.ifr_name[requested_name.size()] = '\0';
    }
    if (::ioctl(device, TUNSETIFF, &request) < 0) {
        const int saved = errno;
        ::close(device);
        errno = saved;
        throw system_failure("TUNSETIFF");
    }

    const int cancellation = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (cancellation < 0) {
        const int saved = errno;
        ::close(device);
        errno = saved;
        throw system_failure("eventfd");
    }

    device_fd_ = device;
    cancel_fd_ = cancellation;
    name_ = request.ifr_name;
    packet_handler_ = std::move(packets);
    error_handler_ = std::move(errors);
    stopping_.store(false, std::memory_order_release);
    try {
        reader_ = std::thread([this] { read_loop(); });
    } catch (...) {
        ::close(cancel_fd_);
        ::close(device_fd_);
        cancel_fd_ = device_fd_ = -1;
        name_.clear();
        packet_handler_ = {};
        error_handler_ = {};
        throw;
    }
}

void LinuxTun::close() noexcept {
    int cancellation = -1;
    {
        std::scoped_lock lock(mutex_);
        if (device_fd_ < 0 && !reader_.joinable()) return;
        stopping_.store(true, std::memory_order_release);
        cancellation = cancel_fd_;
    }
    if (cancellation >= 0) {
        const std::uint64_t signal = 1;
        (void)::write(cancellation, &signal, sizeof(signal));
    }
    if (reader_.joinable() && reader_.get_id() != std::this_thread::get_id()) {
        reader_.join();
    }
    std::scoped_lock lock(mutex_);
    if (device_fd_ >= 0) ::close(device_fd_);
    if (cancel_fd_ >= 0) ::close(cancel_fd_);
    device_fd_ = cancel_fd_ = -1;
    name_.clear();
    packet_handler_ = {};
    error_handler_ = {};
}

bool LinuxTun::write_packet(const std::vector<std::uint8_t>& packet) noexcept {
    if (!valid_ip_packet(packet.data(), packet.size())) return false;
    std::scoped_lock lock(mutex_);
    if (device_fd_ < 0 || stopping_.load(std::memory_order_acquire)) return false;
    for (;;) {
        const ssize_t written = ::write(device_fd_, packet.data(), packet.size());
        if (written == static_cast<ssize_t>(packet.size())) {
            return written > 0;
        }
        if (written < 0 && errno == EINTR) continue;
        return false;
    }
}

bool LinuxTun::is_open() const noexcept {
    std::scoped_lock lock(mutex_);
    return device_fd_ >= 0 && !stopping_.load(std::memory_order_acquire);
}

std::string LinuxTun::name() const {
    std::scoped_lock lock(mutex_);
    return name_;
}

bool LinuxTun::valid_ip_packet(const std::uint8_t* data, const std::size_t size) noexcept {
    if (!data || size == 0 || size > max_packet_size) return false;
    const unsigned version = data[0] >> 4;
    if (version == 4) {
        if (size < 20) return false;
        const std::size_t header = (data[0] & 0x0fU) * 4U;
        const std::size_t total = (static_cast<std::size_t>(data[2]) << 8U) | data[3];
        return header >= 20 && header <= size && total >= header && total <= size;
    }
    if (version == 6) {
        if (size < 40) return false;
        const std::size_t payload = (static_cast<std::size_t>(data[4]) << 8U) | data[5];
        return 40U + payload <= size;
    }
    return false;
}

void LinuxTun::read_loop() noexcept {
    std::vector<std::uint8_t> buffer(max_packet_size);
    for (;;) {
        int device;
        int cancellation;
        PacketHandler handler;
        {
            std::scoped_lock lock(mutex_);
            device = device_fd_;
            cancellation = cancel_fd_;
            handler = packet_handler_;
        }
        pollfd descriptors[2]{{device, POLLIN, 0}, {cancellation, POLLIN, 0}};
        const int ready = ::poll(descriptors, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            report_error(std::string("TUN poll failed: ") + std::strerror(errno));
            return;
        }
        if ((descriptors[1].revents & POLLIN) != 0 ||
            stopping_.load(std::memory_order_acquire)) return;
        if ((descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            report_error("TUN device became unavailable");
            return;
        }
        if ((descriptors[0].revents & POLLIN) == 0) continue;
        const ssize_t count = ::read(device, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            report_error(std::string("TUN read failed: ") + std::strerror(errno));
            return;
        }
        if (count == 0) continue;
        const auto length = static_cast<std::size_t>(count);
        if (!valid_ip_packet(buffer.data(), length)) {
            report_error("TUN discarded a malformed or oversized IP packet");
            continue;
        }
        try {
            handler(std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + length));
        } catch (const std::exception& error) {
            report_error(std::string("TUN packet handler failed: ") + error.what());
        } catch (...) {
            report_error("TUN packet handler failed with an unknown error");
        }
    }
}

void LinuxTun::report_error(std::string message) noexcept {
    ErrorHandler handler;
    {
        std::scoped_lock lock(mutex_);
        handler = error_handler_;
    }
    if (!handler) return;
    try { handler(std::move(message)); } catch (...) {}
}

} // namespace pqvpn::platform

#endif // __linux__
