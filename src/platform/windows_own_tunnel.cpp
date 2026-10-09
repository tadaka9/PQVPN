#ifdef _WIN32

#include "windows_own_tunnel.hpp"

#include <windows.h>

#include <iostream>
#include <stdexcept>
#include <cstring>
#include <chrono>

namespace pqvpn::platform {
namespace {

constexpr LPCWSTR kDefaultDeviceName = L"\\\\.\\PQVPN_TUN0";
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
        std::wstring custom_name;
        if (!device_name_.empty()) {
            const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                device_name_.c_str(), -1, nullptr, 0);
            if (count <= 1) return false;
            custom_name.resize(static_cast<std::size_t>(count));
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                device_name_.c_str(), -1, custom_name.data(), count);
        }
        LPCWSTR name = device_name_.empty() ? kDefaultDeviceName : custom_name.c_str();
        
        handle_ = CreateFileW(
            name,
            GENERIC_READ | GENERIC_WRITE,
            0,                    // No sharing (exclusive access)
            nullptr,              // Default security attributes
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            nullptr);

        if (handle_ == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            // Surface the real reason (access denied, device missing, etc.) so a
            // fail-closed exit in main is diagnosable instead of silent. The
            // device name is wide; the default is \\.\PQVPN_TUN0.
            std::cerr << "PQVPN tunnel device open failed (Windows error " << error
                      << "); is the driver installed and this process elevated?\n";
            return false;
        }

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
    OVERLAPPED overlapped{};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!overlapped.hEvent) return;

    while (!stopping_.load()) {
        ResetEvent(overlapped.hEvent);
        DWORD bytes_read = 0;
        BOOL success = ReadFile(
            handle_,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr,
            &overlapped);

        if (!success) {
            const DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                Sleep(2);
                continue;
            }
            if (error != ERROR_IO_PENDING) break;
            const DWORD wait = WaitForSingleObject(overlapped.hEvent, 250);
            if (wait == WAIT_TIMEOUT) {
                CancelIoEx(handle_, &overlapped);
                GetOverlappedResult(handle_, &overlapped, &bytes_read, TRUE);
                continue;
            }
            if (wait != WAIT_OBJECT_0 ||
                !GetOverlappedResult(handle_, &overlapped, &bytes_read, FALSE)) {
                if (stopping_.load() && GetLastError() == ERROR_OPERATION_ABORTED) break;
                break;
            }
        }

        if (bytes_read > 0 && bytes_read <= kMaxPacketSize) {
            Packet packet(buffer.begin(), buffer.begin() + bytes_read);
            try { inbound_handler_(std::move(packet)); } catch (...) { break; }
        }
    }
    CloseHandle(overlapped.hEvent);
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
        OVERLAPPED overlapped{};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) return false;
        BOOL success = WriteFile(
            handle_,
            packet.data(),
            static_cast<DWORD>(packet.size()),
            nullptr,
            &overlapped);
        if (!success && GetLastError() == ERROR_IO_PENDING) {
            success = GetOverlappedResult(handle_, &overlapped, &bytes_written, TRUE);
        }
        CloseHandle(overlapped.hEvent);
        return success && static_cast<size_t>(bytes_written) == packet.size();

    } catch (...) {
        return false;
    }
}

void WindowsOwnTunnel::close() noexcept {
    try {
        if (!open_.load()) return;

        stopping_.store(true);

        if (handle_ != INVALID_HANDLE_VALUE) CancelIoEx(handle_, nullptr);

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

} // namespace pqvpn::platform

#endif // _WIN32
