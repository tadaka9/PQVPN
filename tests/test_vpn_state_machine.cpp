// Unit tests for VPN state machine (Phase 2 control plane)
#include <catch2/catch_test_macros.hpp>
#include "platform/windows_control/vpn_state_machine.hpp"

using namespace pqvpn::platform;

TEST_CASE("VPN state machine initial state", "[windows][state-machine]") {
    VpnStateMachine sm;
    REQUIRE(sm.get_state() == VpnState::DISCONNECTED);
}

TEST_CASE("VPN state transitions - valid path", "[windows][state-machine]") {
    VpnStateMachine sm;

    // DISCONNECTED -> CONNECTING
    REQUIRE(sm.transition(VpnState::CONNECTING, "user requested connect"));

    // CONNECTING -> CONNECTED
    REQUIRE(sm.transition(VpnState::CONNECTED, "handshake complete"));
    REQUIRE(sm.get_state() == VpnState::CONNECTED);

    // CONNECTED -> DISCONNECTING
    REQUIRE(sm.transition(VpnState::DISCONNECTING, "user requested disconnect"));

    // DISCONNECTING -> DISCONNECTED
    REQUIRE(sm.transition(VpnState::DISCONNECTED, "teardown complete"));
    REQUIRE(sm.get_state() == VpnState::DISCONNECTED);
}

TEST_CASE("VPN state transitions - error path", "[windows][state-machine]") {
    VpnStateMachine sm;

    // DISCONNECTED -> CONNECTING
    REQUIRE(sm.transition(VpnState::CONNECTING));

    // CONNECTING -> ERROR
    REQUIRE(sm.transition(VpnState::STATE_ERROR, "peer timeout"));
    REQUIRE(sm.get_state() == VpnState::STATE_ERROR);

    // ERROR -> RECONNECTING
    REQUIRE(sm.transition(VpnState::RECONNECTING, "auto-reconnect"));

    // RECONNECTING -> CONNECTED
    REQUIRE(sm.transition(VpnState::CONNECTED, "reconnected"));
}

TEST_CASE("VPN state transitions - invalid", "[windows][state-machine]") {
    VpnStateMachine sm;

    // Cannot go directly from DISCONNECTED to CONNECTED
    REQUIRE(!sm.transition(VpnState::CONNECTED));
    REQUIRE(sm.get_state() == VpnState::DISCONNECTED);

    // Cannot go from DISCONNECTED to ERROR
    REQUIRE(!sm.transition(VpnState::STATE_ERROR));
}

TEST_CASE("VPN kill switch", "[windows][state-machine]") {
    VpnStateMachine sm;

    REQUIRE(sm.get_kill_switch() == KillSwitchState::OFF);

    REQUIRE(sm.set_kill_switch(KillSwitchState::ON));
    REQUIRE(sm.get_kill_switch() == KillSwitchState::ON);

    REQUIRE(sm.set_kill_switch(KillSwitchState::OFF));
    REQUIRE(sm.get_kill_switch() == KillSwitchState::OFF);
}

TEST_CASE("VPN state serialization", "[windows][state-machine]") {
    VpnStateMachine sm;

    auto json = sm.serialize_state();
    REQUIRE(json["state"] == "disconnected");
    REQUIRE(json["kill_switch"] == "off");

    sm.transition(VpnState::CONNECTING);
    json = sm.serialize_state();
    REQUIRE(json["state"] == "connecting");
}

TEST_CASE("VPN state change callback", "[windows][state-machine]") {
    VpnStateMachine sm;
    bool callback_fired = false;
    VpnState last_new_state = VpnState::DISCONNECTED;

    sm.on_state_changed([&](const VpnStateChangedEvent& event) {
        callback_fired = true;
        last_new_state = event.new_state;
    });

    sm.transition(VpnState::CONNECTING);
    REQUIRE(callback_fired);
    REQUIRE(last_new_state == VpnState::CONNECTING);
}