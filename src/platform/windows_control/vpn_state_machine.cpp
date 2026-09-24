#ifdef _WIN32

#include "vpn_state_machine.hpp"

namespace pqvpn::platform {

VpnStateMachine::VpnStateMachine() = default;

VpnState VpnStateMachine::get_state() const noexcept {
    return state_.load();
}

bool VpnStateMachine::transition(VpnState new_state, const std::string& reason) {
    VpnState current = state_.load();

    if (!is_valid_transition(current, new_state)) {
        return false;
    }

    // Atomic compare-and-swap to ensure thread-safe transition
    bool swapped = state_.compare_exchange_strong(current, new_state);
    if (!swapped && !is_valid_transition(current, new_state)) {
        return false;
    }

    // Fire state change event
    std::lock_guard<std::mutex> lock(callback_mutex_);
    if (state_changed_callback_) {
        VpnStateChangedEvent event{
            .previous_state = current,
            .new_state = new_state,
            .reason = reason,
            .timestamp = std::chrono::system_clock::now()
        };
        state_changed_callback_(event);
    }

    return state_.load() == new_state;
}

void VpnStateMachine::on_state_changed(StateChangedCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    state_changed_callback_ = std::move(callback);
}

KillSwitchState VpnStateMachine::get_kill_switch() const noexcept {
    return kill_switch_.load();
}

bool VpnStateMachine::set_kill_switch(KillSwitchState state) {
    KillSwitchState previous = kill_switch_.exchange(state);
    return previous != state || state == KillSwitchState::OFF;  // Always succeeds
}

void VpnStateMachine::set_endpoint(const EndpointConfig& endpoint) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    endpoint_config_ = endpoint;
}

std::optional<EndpointConfig> VpnStateMachine::get_endpoint() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return endpoint_config_;
}

bool VpnStateMachine::set_startpoint(const StartpointConfig& startpoint) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    if (startpoint.ip_address.empty()) {
        return false;  // Invalid: empty IP address
    }
    startpoint_config_ = startpoint;
    return startpoint_config_.has_value();
}

std::optional<StartpointConfig> VpnStateMachine::get_startpoint() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return startpoint_config_;
}

nlohmann::json VpnStateMachine::serialize_state() const {
    nlohmann::json j;
    j["state"] = state_name(get_state());
    j["kill_switch"] = (get_kill_switch() == KillSwitchState::ON) ? "on" : "off";
    return j;
}

bool VpnStateMachine::is_valid_transition(VpnState from, VpnState to) const {
    // State transition table:
    // DISCONNECTED -> CONNECTING
    // CONNECTING   -> CONNECTED | ERROR | DISCONNECTED
    // CONNECTED    -> DISCONNECTING | ERROR | RECONNECTING
    // DISCONNECTING-> DISCONNECTED
    // ERROR        -> RECONNECTING | DISCONNECTED
    // RECONNECTING -> CONNECTED | ERROR | DISCONNECTED

    switch (from) {
        case VpnState::DISCONNECTED:
            return to == VpnState::CONNECTING;

        case VpnState::CONNECTING:
            return to == VpnState::CONNECTED ||
                   to == VpnState::STATE_ERROR ||
                   to == VpnState::DISCONNECTED;

        case VpnState::CONNECTED:
            return to == VpnState::DISCONNECTING ||
                   to == VpnState::STATE_ERROR ||
                   to == VpnState::RECONNECTING;

        case VpnState::DISCONNECTING:
            return to == VpnState::DISCONNECTED;

        case VpnState::STATE_ERROR:
            return to == VpnState::RECONNECTING ||
                   to == VpnState::DISCONNECTED;

        case VpnState::RECONNECTING:
            return to == VpnState::CONNECTED ||
                   to == VpnState::STATE_ERROR ||
                   to == VpnState::DISCONNECTED;

        default:
            return false;
    }
}

std::string VpnStateMachine::state_name(VpnState state) {
    switch (state) {
        case VpnState::DISCONNECTED:  return "disconnected";
        case VpnState::CONNECTING:    return "connecting";
        case VpnState::CONNECTED:     return "connected";
        case VpnState::DISCONNECTING: return "disconnecting";
        case VpnState::STATE_ERROR:   return "error";
        case VpnState::RECONNECTING:  return "reconnecting";
        default:                      return "unknown";
    }
}

} // namespace pqvpn::platform

#endif // _WIN32