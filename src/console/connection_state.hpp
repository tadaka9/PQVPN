#pragma once
#include <string_view>

namespace pqvpn::console {
enum class ConnectionPhase { Disconnected, Connecting, Securing, Relay, Protected, Stopping, Failed };
struct ConnectionSnapshot {
    bool active = false;
    bool authenticated = false;
    bool tunnel_ready = false;
    bool relay_only = false;
    bool stopping = false;
    bool failed = false;
};
constexpr ConnectionPhase connection_phase(ConnectionSnapshot state) {
    if(state.failed&&!state.stopping)return ConnectionPhase::Failed;
    if (!state.active) return ConnectionPhase::Disconnected;
    if (state.stopping) return ConnectionPhase::Stopping;
    if (!state.authenticated) return ConnectionPhase::Connecting;
    if (state.relay_only) return ConnectionPhase::Relay;
    return state.tunnel_ready ? ConnectionPhase::Protected : ConnectionPhase::Securing;
}
constexpr std::string_view phase_label(ConnectionPhase phase) {
    switch (phase) {
    case ConnectionPhase::Connecting: return "Connecting";
    case ConnectionPhase::Securing: return "Peer ready - securing routes";
    case ConnectionPhase::Relay: return "Connected - relay only";
    case ConnectionPhase::Protected: return "Protected";
    case ConnectionPhase::Stopping: return "Disconnecting";
    case ConnectionPhase::Failed: return "Connection failed";
    default: return "Disconnected";
    }
}
constexpr std::string_view phase_color(ConnectionPhase phase) {
    switch (phase) {
    case ConnectionPhase::Relay:
    case ConnectionPhase::Protected: return "#34d399";
    case ConnectionPhase::Connecting:
    case ConnectionPhase::Securing:
    case ConnectionPhase::Stopping: return "#fbbf24";
    case ConnectionPhase::Failed: return "#f87171";
    default: return "#94a3b8";
    }
}
}
