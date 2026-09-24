#pragma once

#ifdef _WIN32

// Must include winsock2.h before windows.h to avoid conflicts with asio
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <nlohmann/json.hpp>

#include "vpn_state_machine.hpp"
#include "routing/route_transaction.hpp"

namespace pqvpn::platform {

// External control channel server on \\.\pipe\pqvpn-tun-ctl
// Accepts JSON commands and returns JSON responses.
class ControlChannelServer {
public:
    ControlChannelServer(VpnStateMachine& state_machine, routing::RouteBackend& route_backend);
    ~ControlChannelServer();

    // Start listening for client connections
    bool start();

    // Stop the server
    void stop();

    [[nodiscard]] bool is_running() const noexcept;

private:
    void accept_loop();
    void handle_client(HANDLE client_handle);
    nlohmann::json handle_command(const std::string& command_json);
    nlohmann::json handle_routes_add(const nlohmann::json& params);
    nlohmann::json handle_routes_remove(const nlohmann::json& params);
    nlohmann::json handle_routes_list();
    nlohmann::json handle_routes_set(const nlohmann::json& params);
    nlohmann::json handle_set_endpoint(const nlohmann::json& params);
    nlohmann::json handle_get_endpoints();
    nlohmann::json handle_set_startpoint(const nlohmann::json& params);
    nlohmann::json handle_get_startpoint();

    VpnStateMachine& state_machine_;
    routing::RouteBackend& route_backend_;
    HANDLE pipe_handle_ = INVALID_HANDLE_VALUE;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
};

} // namespace pqvpn::platform

#endif // _WIN32