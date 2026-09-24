#ifdef _WIN32

#include "control_channel.hpp"

// Prevent windows.h from including winsock.h (we want winsock2.h)
#define _WINSOCKAPI_
#include <windows.h>
#include <sddl.h>
#include <asio/ip/address.hpp>
#include <system_error>  // For security descriptor strings

namespace pqvpn::platform {
namespace {

constexpr LPCWSTR kPipeName = L"\\\\.\\pipe\\pqvpn-tun-ctl";
constexpr DWORD kBufferSize = 4096;

// ACL: SYSTEM + Administrators can access the pipe
constexpr LPCWSTR kPipeSecurityDescriptor =
    L"D:(A;;GA;;;SY)(A;;GA;;;BA)";

std::string wide_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &result[0], size);
    return result;
}

} // namespace

ControlChannelServer::ControlChannelServer(VpnStateMachine& state_machine, routing::RouteBackend& route_backend)
    : state_machine_(state_machine), route_backend_(route_backend) {
    pipe_handle_ = CreateNamedPipeW(
        kPipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        kBufferSize,
        kBufferSize,
        0,
        nullptr);
}

ControlChannelServer::~ControlChannelServer() {
    stop();
    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_handle_);
    }
}

bool ControlChannelServer::start() {
    if (running_.exchange(true)) {
        return pipe_handle_ != INVALID_HANDLE_VALUE;  // Already running
    }
    accept_thread_ = std::thread(&ControlChannelServer::accept_loop, this);
    return pipe_handle_ != INVALID_HANDLE_VALUE;
}

void ControlChannelServer::stop() {
    if (!running_.exchange(false)) return;

    // Disconnect any current client to unblock ConnectNamedPipe
    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(pipe_handle_);
    }

    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
}

bool ControlChannelServer::is_running() const noexcept {
    return running_.load();
}

void ControlChannelServer::accept_loop() {
    while (running_.load()) {
        // Wait for a client to connect
        BOOL connected = ConnectNamedPipe(pipe_handle_, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            break;  // Error or stopped
        }

        // Handle the client in a separate thread so we can accept more connections
        std::thread client_thread(&ControlChannelServer::handle_client, this, pipe_handle_);
        client_thread.detach();

        // Prepare for next connection
        if (!DisconnectNamedPipe(pipe_handle_)) {
            break;
        }
    }
}

void ControlChannelServer::handle_client(HANDLE client) {
    char buffer[kBufferSize];

    while (running_.load()) {
        DWORD bytes_read = 0;
        BOOL success = ReadFile(client, buffer, kBufferSize - 1, &bytes_read, nullptr);
        if (!success || bytes_read == 0) {
            break;  // Client disconnected or error
        }

        buffer[bytes_read] = '\0';
        std::string command(buffer);

        // Parse and handle the command
        nlohmann::json response;
        try {
            response = handle_command(command);
        } catch (const std::exception& e) {
            response["error"] = e.what();
        }

        // Send response back to client
        std::string response_str = response.dump();
        DWORD bytes_written = 0;
        WriteFile(client, response_str.c_str(), static_cast<DWORD>(response_str.size()), &bytes_written, nullptr);
    }
}

nlohmann::json ControlChannelServer::handle_command(const std::string& command_json) {
    nlohmann::json cmd = nlohmann::json::parse(command_json);
    std::string method = cmd.value("method", "");

    if (method == "get_state") {
        return state_machine_.serialize_state();
    }

    if (method == "connect") {
        bool ok = state_machine_.transition(VpnState::CONNECTING, "connect command");
        nlohmann::json resp;
        resp["ok"] = ok;
        if (!ok) {
            resp["error"] = "invalid state transition";
        }
        return resp;
    }

    if (method == "disconnect") {
        bool ok = state_machine_.transition(VpnState::DISCONNECTING, "disconnect command");
        nlohmann::json resp;
        resp["ok"] = ok;
        if (!ok) {
            resp["error"] = "invalid state transition";
        }
        return resp;
    }

    if (method == "get_kill_switch") {
        nlohmann::json resp;
        resp["kill_switch"] = (state_machine_.get_kill_switch() == KillSwitchState::ON) ? "on" : "off";
        return resp;
    }

    if (method == "set_kill_switch") {
        std::string value = cmd.value("value", "off");
        KillSwitchState state = (value == "on") ? KillSwitchState::ON : KillSwitchState::OFF;
        bool ok = state_machine_.set_kill_switch(state);
        nlohmann::json resp;
        resp["ok"] = ok;
        return resp;
    }

    if (method == "routes_add") {
        return handle_routes_add(cmd.value("params", nlohmann::json::object()));
    }

    if (method == "routes_remove") {
        return handle_routes_remove(cmd.value("params", nlohmann::json::object()));
    }

    if (method == "routes_list") {
        return handle_routes_list();
    }

    if (method == "routes_set") {
        return handle_routes_set(cmd.value("params", nlohmann::json::array()));
    }

    if (method == "set_endpoint") {
        return handle_set_endpoint(cmd.value("params", nlohmann::json::object()));
    }

    if (method == "get_endpoints") {
        return handle_get_endpoints();
    }

    if (method == "set_startpoint") {
        return handle_set_startpoint(cmd.value("params", nlohmann::json::object()));
    }

    if (method == "get_startpoint") {
        return handle_get_startpoint();
    }

    // Unknown command
    nlohmann::json resp;
    resp["error"] = "unknown method: " + method;
    return resp;
}

nlohmann::json ControlChannelServer::handle_routes_add(const nlohmann::json& params) {
    try {
        std::string prefix_str = params.value("prefix", "");
        std::string next_hop_str = params.value("next_hop", "");
        int prefix_length = params.value("prefix_length", 0);

        if (prefix_str.empty() || next_hop_str.empty()) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "prefix and next_hop are required";
            return resp;
        }

        std::error_code ec;
        asio::ip::address prefix;
        try {
            prefix = asio::ip::make_address(prefix_str, ec);
        } catch (...) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "invalid prefix address: " + prefix_str;
            return resp;
        }
        if (ec) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "invalid prefix address: " + ec.message();
            return resp;
        }

        asio::ip::address next_hop;
        try {
            next_hop = asio::ip::make_address(next_hop_str, ec);
        } catch (...) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "invalid next_hop address: " + next_hop_str;
            return resp;
        }
        if (ec) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "invalid next_hop address: " + ec.message();
            return resp;
        }

        routing::RouteEntry entry{
            prefix,
            static_cast<uint8_t>(prefix_length),
            next_hop,
            0  // Let backend resolve interface index
        };

        auto result = route_backend_.install(entry);

        nlohmann::json resp;
        resp["ok"] = result.ok;
        if (!result.ok) {
            resp["error"] = result.error;
        }
        return resp;
    } catch (const std::exception& e) {
        nlohmann::json resp;
        resp["ok"] = false;
        resp["error"] = e.what();
        return resp;
    }
}

nlohmann::json ControlChannelServer::handle_routes_remove(const nlohmann::json& params) {
    try {
        std::string prefix_str = params.value("prefix", "");
        int prefix_length = params.value("prefix_length", 0);

        if (prefix_str.empty()) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "prefix is required";
            return resp;
        }

        std::error_code ec;
        asio::ip::address prefix;
        try {
            prefix = asio::ip::make_address(prefix_str, ec);
        } catch (...) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "invalid prefix address: " + prefix_str;
            return resp;
        }
        if (ec) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "invalid prefix address: " + ec.message();
            return resp;
        }

        // Route removal requires a gateway address; use the default route target
        asio::ip::address removal_gateway = asio::ip::make_address("0.0.0.0", ec);
        routing::RouteEntry entry{
            prefix,
            static_cast<uint8_t>(prefix_length),
            removal_gateway,
            0
        };

        auto result = route_backend_.remove(entry);

        nlohmann::json resp;
        resp["ok"] = result.ok;
        if (!result.ok) {
            resp["error"] = result.error;
        }
        return resp;
    } catch (const std::exception& e) {
        nlohmann::json resp;
        resp["ok"] = false;
        resp["error"] = e.what();
        return resp;
    }
}

nlohmann::json ControlChannelServer::handle_routes_list() {
    // Route listing requires querying the OS routing table via GetIpForwardTable.
    // Returns empty list until that integration is complete.
    nlohmann::json resp;
    resp["routes"] = nlohmann::json::array();
    return resp;
}

nlohmann::json ControlChannelServer::handle_routes_set(const nlohmann::json& params) {
    try {
        routing::RouteTransaction transaction;

        for (const auto& route : params) {
            std::string prefix_str = route.value("prefix", "");
            std::string next_hop_str = route.value("next_hop", "");
            int prefix_length = route.value("prefix_length", 0);

            if (prefix_str.empty() || next_hop_str.empty()) {
                continue;  // Skip invalid entries
            }

            std::error_code ec;
            asio::ip::address prefix;
            try {
                prefix = asio::ip::make_address(prefix_str, ec);
            } catch (...) { continue; }
            if (ec) continue;

            asio::ip::address next_hop;
            try {
                next_hop = asio::ip::make_address(next_hop_str, ec);
            } catch (...) { continue; }
            if (ec) continue;

            transaction.add(routing::RouteEntry{
                prefix,
                static_cast<uint8_t>(prefix_length),
                next_hop,
                0
            });
        }

        auto report = transaction.commit(route_backend_);

        nlohmann::json resp;
        resp["ok"] = report.committed;
        if (!report.committed) {
            resp["error"] = report.error;
            resp["failed_index"] = report.failed_index;
        }
        return resp;
    } catch (const std::exception& e) {
        nlohmann::json resp;
        resp["ok"] = false;
        resp["error"] = e.what();
        return resp;
    }
}

nlohmann::json ControlChannelServer::handle_set_endpoint(const nlohmann::json& params) {
    try {
        std::string address = params.value("address", "");
        uint16_t port = static_cast<uint16_t>(params.value("port", 0));
        std::string peer_id = params.value("peer_id", "");

        if (address.empty()) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "address is required";
            return resp;
        }

        EndpointConfig endpoint{address, port, peer_id};
        state_machine_.set_endpoint(endpoint);

        nlohmann::json resp;
        resp["ok"] = true;
        return resp;
    } catch (const std::exception& e) {
        nlohmann::json resp;
        resp["ok"] = false;
        resp["error"] = e.what();
        return resp;
    }
}

nlohmann::json ControlChannelServer::handle_get_endpoints() {
    auto endpoint = state_machine_.get_endpoint();
    nlohmann::json resp;
    if (endpoint) {
        resp["endpoints"] = nlohmann::json::array({{
            {"address", endpoint->address},
            {"port", endpoint->port},
            {"peer_id", endpoint->peer_id}
        }});
    } else {
        resp["endpoints"] = nlohmann::json::array();
    }
    return resp;
}

nlohmann::json ControlChannelServer::handle_set_startpoint(const nlohmann::json& params) {
    try {
        std::string ip_address = params.value("ip", "");
        int prefix_length = params.value("prefix", 0);

        if (ip_address.empty()) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "ip is required";
            return resp;
        }

        // Validate IP address format
        std::error_code ec;
        asio::ip::make_address(ip_address, ec);
        if (ec) {
            nlohmann::json resp;
            resp["ok"] = false;
            resp["error"] = "invalid ip address: " + ec.message();
            return resp;
        }

        StartpointConfig startpoint{ip_address, prefix_length};
        bool ok = state_machine_.set_startpoint(startpoint);

        nlohmann::json resp;
        resp["ok"] = ok;
        if (!ok) {
            resp["error"] = "failed to set startpoint";
        }
        return resp;
    } catch (const std::exception& e) {
        nlohmann::json resp;
        resp["ok"] = false;
        resp["error"] = e.what();
        return resp;
    }
}

nlohmann::json ControlChannelServer::handle_get_startpoint() {
    auto startpoint = state_machine_.get_startpoint();
    nlohmann::json resp;
    if (startpoint) {
        resp["ip"] = startpoint->ip_address;
        resp["prefix"] = startpoint->prefix_length;
    } else {
        resp["ip"] = nullptr;
        resp["prefix"] = nullptr;
    }
    return resp;
}

} // namespace pqvpn::platform

#endif // _WIN32