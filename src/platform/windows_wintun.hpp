#pragma once

#ifdef _WIN32

#include <cstdint>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "tunnel/packet_tunnel.hpp"

namespace pqvpn::platform {

// Wintun is loaded at runtime. The application must place an authentic
// wintun.dll next to the executable. The secure loader also permits System32.
class WindowsWintun final : public tunnel::PacketTunnel {
public:
    using PacketHandler = tunnel::PacketTunnel::PacketHandler;
    using ErrorHandler = tunnel::PacketTunnel::ErrorHandler;

    explicit WindowsWintun(std::string adapter_name = "PQVPN")
        : configured_name_(std::move(adapter_name)) {}
    WindowsWintun(const WindowsWintun&) = delete;
    WindowsWintun& operator=(const WindowsWintun&) = delete;
    ~WindowsWintun();

    // Opens an existing adapter or creates it when it is absent. An empty name
    // selects "PQVPN". Packets delivered to handler are raw layer-3 packets.
    void open(const std::string& adapter_name, PacketHandler handler);
    void start(PacketHandler packet_handler, ErrorHandler error_handler) override;
    void write(std::span<const uint8_t> packet) override;
    void stop() noexcept override { close(); }
    void close() noexcept;

    bool is_open() const noexcept;
    bool is_running() const noexcept override { return is_open(); }
    tunnel::PacketLayer layer() const noexcept override { return tunnel::PacketLayer::network; }
    std::string name() const override;

private:
    struct Api;
    void receive_loop(std::stop_token stop_token) noexcept;

    mutable std::mutex mutex_;
    HMODULE module_ = nullptr;
    Api* api_ = nullptr;
    void* adapter_ = nullptr;
    void* session_ = nullptr;
    HANDLE stop_event_ = nullptr;
    std::string configured_name_;
    std::string name_;
    PacketHandler handler_;
    ErrorHandler error_handler_;
    std::jthread receiver_;
};

} // namespace pqvpn::platform

#endif
