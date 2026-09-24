// Unit tests for control channel command handling (Phase 3)
#include <catch2/catch_test_macros.hpp>
#include "platform/windows_control/vpn_state_machine.hpp"

using namespace pqvpn::platform;

TEST_CASE("Endpoint configuration round-trip", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Initially no endpoint configured
    REQUIRE(!sm.get_endpoint().has_value());

    // Set endpoint
    EndpointConfig ep{"192.168.1.100", 9090, "peer-abc"};
    sm.set_endpoint(ep);

    // Verify it was stored correctly
    auto retrieved = sm.get_endpoint();
    REQUIRE(retrieved.has_value());
    REQUIRE(retrieved->address == "192.168.1.100");
    REQUIRE(retrieved->port == 9090);
    REQUIRE(retrieved->peer_id == "peer-abc");
}

TEST_CASE("Startpoint configuration validation", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Initially no startpoint configured
    REQUIRE(!sm.get_startpoint().has_value());

    // Empty IP should fail
    StartpointConfig invalid{"", 24};
    REQUIRE(!sm.set_startpoint(invalid));
    REQUIRE(!sm.get_startpoint().has_value());

    // Valid configuration should succeed
    StartpointConfig valid{"10.8.0.1", 24};
    REQUIRE(sm.set_startpoint(valid));

    auto retrieved = sm.get_startpoint();
    REQUIRE(retrieved.has_value());
    REQUIRE(retrieved->ip_address == "10.8.0.1");
    REQUIRE(retrieved->prefix_length == 24);
}

TEST_CASE("Multiple endpoint updates", "[windows][control-channel]") {
    VpnStateMachine sm;

    // First endpoint
    EndpointConfig ep1{"192.168.1.100", 9090, ""};
    sm.set_endpoint(ep1);
    REQUIRE(sm.get_endpoint()->address == "192.168.1.100");

    // Update to different endpoint
    EndpointConfig ep2{"10.0.0.50", 8443, "peer-xyz"};
    sm.set_endpoint(ep2);
    auto retrieved = sm.get_endpoint();
    REQUIRE(retrieved->address == "10.0.0.50");
    REQUIRE(retrieved->port == 8443);
    REQUIRE(retrieved->peer_id == "peer-xyz");
}

TEST_CASE("State serialization includes configuration", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Set some configuration
    EndpointConfig ep{"192.168.1.100", 9090, ""};
    sm.set_endpoint(ep);

    StartpointConfig sp{"10.8.0.1", 24};
    sm.set_startpoint(sp);

    // Transition to connecting state
    sm.transition(VpnState::CONNECTING);

    // Serialize and verify structure
    auto json = sm.serialize_state();
    REQUIRE(json.contains("state"));
    REQUIRE(json["state"] == "connecting");
    REQUIRE(json.contains("kill_switch"));
}

TEST_CASE("IP assignment round-trip", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Initially no IPs assigned
    auto initial = sm.enumerate_ips();
    REQUIRE(initial.empty());

    // Assign multiple IPs
    std::vector<std::string> ips = {"10.8.0.1", "10.8.0.2", "fd00::1"};
    REQUIRE(sm.assign_ips(ips));

    // Verify they were stored correctly
    auto retrieved = sm.enumerate_ips();
    REQUIRE(retrieved.size() == 3);
    REQUIRE(retrieved[0] == "10.8.0.1");
    REQUIRE(retrieved[1] == "10.8.0.2");
    REQUIRE(retrieved[2] == "fd00::1");
}

TEST_CASE("IP assignment validation", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Empty address should fail
    std::vector<std::string> invalid = {""};
    REQUIRE(!sm.assign_ips(invalid));

    // Valid single IP should succeed
    std::vector<std::string> valid = {"192.168.1.1"};
    REQUIRE(sm.assign_ips(valid));
    REQUIRE(sm.enumerate_ips().size() == 1);
}

TEST_CASE("IP reassignment replaces previous", "[windows][control-channel]") {
    VpnStateMachine sm;

    // First assignment
    std::vector<std::string> first = {"10.8.0.1"};
    REQUIRE(sm.assign_ips(first));
    REQUIRE(sm.enumerate_ips().size() == 1);

    // Second assignment replaces the first
    std::vector<std::string> second = {"172.16.0.1", "172.16.0.2"};
    REQUIRE(sm.assign_ips(second));
    auto retrieved = sm.enumerate_ips();
    REQUIRE(retrieved.size() == 2);
    REQUIRE(retrieved[0] == "172.16.0.1");
}

TEST_CASE("IP assignment with mixed IPv4 and IPv6", "[windows][control-channel]") {
    VpnStateMachine sm;

    std::vector<std::string> mixed = {"192.168.1.1", "fd00::dead:beef", "10.0.0.1"};
    REQUIRE(sm.assign_ips(mixed));
    auto retrieved = sm.enumerate_ips();
    REQUIRE(retrieved.size() == 3);
    REQUIRE(retrieved[1] == "fd00::dead:beef");
}

TEST_CASE("IP assignment preserves order", "[windows][control-channel]") {
    VpnStateMachine sm;

    std::vector<std::string> ordered = {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"};
    REQUIRE(sm.assign_ips(ordered));
    auto retrieved = sm.enumerate_ips();
    for (size_t i = 0; i < ordered.size(); ++i) {
        REQUIRE(retrieved[i] == ordered[i]);
    }
}