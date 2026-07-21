#pragma once

#ifdef _WIN32

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>

namespace pqvpn::platform {

class WindowsTap {
public:
    using PacketHandler = std::function<void(std::vector<uint8_t>)>;

    WindowsTap() = default;
    WindowsTap(const WindowsTap&) = delete;
    WindowsTap& operator=(const WindowsTap&) = delete;
    ~WindowsTap();

    void open(const std::string& requested_guid, PacketHandler handler);
    void write(const std::vector<uint8_t>& ethernet_frame);
    void close() noexcept;
    bool is_open() const noexcept { return device_ != INVALID_HANDLE_VALUE; }
    const std::string& guid() const noexcept { return guid_; }

private:
    static std::string find_adapter_guid();
    void read_loop(std::stop_token stop_token);

    HANDLE device_ = INVALID_HANDLE_VALUE;
    std::string guid_;
    PacketHandler handler_;
    std::jthread reader_;
};

} // namespace pqvpn::platform

#endif
