#ifdef _WIN32

#include "windows_own_tunnel.hpp"

#include <windows.h>

#include <stdexcept>
#include <cstring>
#include <chrono>

namespace pqvpn::platform {
namespace {

constexpr LPCWSTR kDefaultDeviceName = L"\\\\.\\PQVPN_TUN0";
constexpr DWORD kReadTimeoutMs = 100;
constexpr size_t kMaxPacketSize = 65536;

std::runtime_error windows_error(const std::string& operation, DWORD code = GetLastError()) {
    return std::runtime_error(operation + " failed (Windows error " + std::to_string(code) + ")");
}

} // namespace

WindowsOwnTunnel::~WindowsOwnTunnel() {
    close();
}

bool WindowsOwnTunnel::open(InboundHandler inbound) {
    if (!inbound) return false;
    
    try {
        stopping_.store(false);
        inbound_handler_ = std::move(inbound);

        // Open the device file created by our NDIS driver
        LPCWSTR name = (device_name_.empty()) ? kDefaultDeviceName : 
            reinterpret_cast<LPCWSTR>(device_name_.c_str());
        
        handle_ = CreateFileW(
            name,
            GENERIC_READ | GENERIC_WRITE,
            0,                    // No sharing (exclusive access)
            nullptr,              // Default security attributes
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (handle_ == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            // Failed to open device - caller will handle logging
            return false;
        }

        // Configure timeouts for non-blocking reads
        COMMTIMEOUTS timeouts = {};
        timeouts.ReadIntervalTimeout = kReadTimeoutMs;
        timeouts.ReadTotalTimeoutConstant = kReadTimeoutMs;
        SetCommTimeouts(handle_, &timeouts);

        open_.store(true);

        // Start the receive loop thread
        receiver_thread_ = std::thread(&WindowsOwnTunnel::receive_loop, this);

        return handle_ != INVALID_HANDLE_VALUE;

    } catch (...) {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
        return false;
    }
}

void WindowsOwnTunnel::receive_loop() {
    std::vector<uint8_t> buffer(kMaxPacketSize);

    while (!stopping_.load()) {
        DWORD bytes_read = 0;
        BOOL success = ReadFile(
            handle_,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytes_read,
            nullptr);

        if (!success) {
            const DWORD error = GetLastError();
            if (error == ERROR_TIMEOUT || error == ERROR_IO_PENDING) {
                // Timeout or pending I/O - continue polling
                continue;
            }

            break;
        }

        if (bytes_read > 0 && bytes_read <= kMaxPacketSize) {
            Packet packet(buffer.begin(), buffer.begin() + bytes_read);
            
            // Enqueue with backpressure
            if (!enqueue_packet(std::move(packet))) {

            }
        }
    }

    // Drain remaining packets on exit
    drain_queues();
}

bool WindowsOwnTunnel::write(const Packet& packet) noexcept {
    if (packet.empty() || packet.size() > kMaxPacketSize) {
        return false;
    }

    try {
        std::lock_guard<std::mutex> lock(write_mutex_);
        
        if (!open_.load() || handle_ == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD bytes_written = 0;
        BOOL success = WriteFile(
            handle_,
            packet.data(),
            static_cast<DWORD>(packet.size()),
            &bytes_written,
            nullptr);

        return success && static_cast<size_t>(bytes_written) == packet.size();

    } catch (...) {
        return false;
    }
}

void WindowsOwnTunnel::close() noexcept {
    try {
        if (!open_.load()) return;

        stopping_.store(true);

        // Wait for receiver thread to finish
        if (receiver_thread_.joinable()) {
            receiver_thread_.join();
        }

        // Close the device handle
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }

        open_.store(false);

    } catch (...) {
        // Best-effort cleanup
    }
}

bool WindowsOwnTunnel::is_open() const noexcept {
    return open_.load();
}

std::string WindowsOwnTunnel::describe() const {
    if (device_name_.empty()) {
        return "PQVPN tunnel driver (default device)";
    }
    return "PQVPN tunnel driver (" + device_name_ + ")";
}

bool WindowsOwnTunnel::enqueue_packet(Packet&& packet) {
    size_t current_size = queue_size_.load();
    if (current_size >= kQueueCapacity) {
        return false; // Queue full - backpressure
    }

    size_t tail = queue_tail_.fetch_add(1);
    receive_queue_[tail % kQueueCapacity] = std::move(packet);
    queue_size_.store(current_size + 1);
    return current_size < kQueueCapacity;
}

std::vector<uint8_t> WindowsOwnTunnel::dequeue_packet() {
    size_t head = queue_head_.fetch_add(1);
    Packet packet = std::move(receive_queue_[head % kQueueCapacity]);
    queue_size_.store(queue_size_.load() - 1);
    return packet;
}

void WindowsOwnTunnel::drain_queues() {
    while (queue_size_.load() > 0) {
        Packet packet = dequeue_packet();
        try {
            if (inbound_handler_) {
                inbound_handler_(std::move(packet));
            }
        } catch (...) {
            // Best-effort delivery during drain
        }
    }
}

} // namespace pqvpn::platform

#endif // _WIN32