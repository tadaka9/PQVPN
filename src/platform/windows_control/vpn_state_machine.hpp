#pragma once

#ifdef _WIN32

#include <string>
#include <atomic>
#include <mutex>
#include <optional>
#include <functional>
#include <chrono>
#include <vector>
#include <nlohmann/json.hpp>

namespace pqvpn::platform {

// VPN connection states (fail-closed design)
enum class VpnState {
    DISCONNECTED,     // No active tunnel
    CONNECTING,       // Adapter up + routes being installed
    CONNECTED,        // Active tunnel with traffic flowing
    DISCONNECTING,    // Tearing down routes and adapter
    STATE_ERROR,      // Peer lost or fatal error (adapter may still be up)
    RECONNECTING      // Attempting to re-establish connection
};

// Kill switch states
enum class KillSwitchState {
    OFF,              // Normal routing when disconnected
    ON               // Blackhole all egress when not connected
};

// Endpoint configuration (remote peer)
struct EndpointConfig {
    std::string address;      // IP or hostname
    uint16_t port = 0;
    std::string peer_id;      // Optional: specific peer identity
};

// Startpoint configuration (local interface)
struct StartpointConfig {
    std::string ip_address;
    int prefix_length = 0;
};

// State change event data
struct VpnStateChangedEvent {
    VpnState previous_state;
    VpnState new_state;
    std::string reason;
    std::chrono::system_clock::time_point timestamp;
};

// Callback for state changes
using StateChangedCallback = std::function<void(const VpnStateChangedEvent&)>;

class VpnStateMachine {
public:
    VpnStateMachine();
    ~VpnStateMachine() = default;

    // Get current state
    [[nodiscard]] VpnState get_state() const noexcept;

    // Transition to a new state (validates transition is legal)
    bool transition(VpnState new_state, const std::string& reason = "");

    // Register callback for state changes
    void on_state_changed(StateChangedCallback callback);

    // Kill switch control
    [[nodiscard]] KillSwitchState get_kill_switch() const noexcept;
    bool set_kill_switch(KillSwitchState state);

    // Endpoint configuration
    void set_endpoint(const EndpointConfig& endpoint);
    [[nodiscard]] std::optional<EndpointConfig> get_endpoint() const;

    // Startpoint configuration
    bool set_startpoint(const StartpointConfig& startpoint);
    [[nodiscard]] std::optional<StartpointConfig> get_startpoint() const;

    // Serialize current state to JSON (for control channel)
    nlohmann::json serialize_state() const;

private:
    std::atomic<VpnState> state_{VpnState::DISCONNECTED};
    std::atomic<KillSwitchState> kill_switch_{KillSwitchState::OFF};
    mutable std::mutex config_mutex_;
    std::optional<EndpointConfig> endpoint_config_;
    std::optional<StartpointConfig> startpoint_config_;
    mutable std::mutex callback_mutex_;
    StateChangedCallback state_changed_callback_;

    // Validate that a transition is legal
    bool is_valid_transition(VpnState from, VpnState to) const;

    // Get human-readable name for a state
    static std::string state_name(VpnState state);
};

} // namespace pqvpn::platform

#endif // _WIN32