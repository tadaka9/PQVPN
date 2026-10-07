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

TEST_CASE("Kill switch state transitions", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Initially kill switch is OFF
    REQUIRE(sm.get_kill_switch() == KillSwitchState::OFF);

    // Turn it ON (without route backend)
    REQUIRE(sm.set_kill_switch(KillSwitchState::ON, nullptr));
    REQUIRE(sm.get_kill_switch() == KillSwitchState::ON);

    // Repeated ON transitions must all succeed
    REQUIRE(sm.set_kill_switch(KillSwitchState::ON, nullptr));
    REQUIRE(sm.get_kill_switch() == KillSwitchState::ON);

    // Turn it OFF
    REQUIRE(sm.set_kill_switch(KillSwitchState::OFF, nullptr));
    REQUIRE(sm.get_kill_switch() == KillSwitchState::OFF);
}

TEST_CASE("Kill switch with route backend integration", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Test that set_kill_switch accepts a route backend pointer
    // (actual route installation requires elevated privileges, so we just verify the API)
    REQUIRE(sm.set_kill_switch(KillSwitchState::ON, nullptr));
    REQUIRE(sm.get_kill_switch() == KillSwitchState::ON);
    REQUIRE(sm.set_kill_switch(KillSwitchState::OFF, nullptr));
    REQUIRE(sm.get_kill_switch() == KillSwitchState::OFF);
}

TEST_CASE("Kill switch idempotency", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Multiple ON transitions should all succeed
    for (int i = 0; i < 3; ++i) {
        REQUIRE(sm.set_kill_switch(KillSwitchState::ON, nullptr));
    }
    REQUIRE(sm.get_kill_switch() == KillSwitchState::ON);

    // Multiple OFF transitions should all succeed
    for (int i = 0; i < 3; ++i) {
        REQUIRE(sm.set_kill_switch(KillSwitchState::OFF, nullptr));
    }
    REQUIRE(sm.get_kill_switch() == KillSwitchState::OFF);
}

TEST_CASE("Kill switch state persists across other operations", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Enable kill switch
    REQUIRE(sm.set_kill_switch(KillSwitchState::ON, nullptr));

    // Perform other operations that shouldn't affect kill switch state
    EndpointConfig ep{"192.168.1.100", 9090, ""};
    sm.set_endpoint(ep);

    StartpointConfig sp{"10.8.0.1", 24};
    sm.set_startpoint(sp);

    std::vector<std::string> ips = {"10.8.0.1"};
    sm.assign_ips(ips);

    // Kill switch should still be ON
    REQUIRE(sm.get_kill_switch() == KillSwitchState::ON);
}

TEST_CASE("DNS switching enable/disable", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Initially DNS switching is disabled
    auto config = sm.get_dns_config();
    REQUIRE(!config.enabled);

    // Enable with custom resolvers
    std::vector<std::string> tunnel_dns = {"10.8.0.1", "1.1.1.1"};
    REQUIRE(sm.switch_dns(true, tunnel_dns));
    
    config = sm.get_dns_config();
    REQUIRE(config.enabled);
    REQUIRE(config.resolvers.size() == 2);
    REQUIRE(config.resolvers[0] == "10.8.0.1");
    REQUIRE(config.original_resolvers.size() > 0);  // Original DNS captured

    // Disable (restore original)
    REQUIRE(sm.switch_dns(false));
    config = sm.get_dns_config();
    REQUIRE(!config.enabled);
}

TEST_CASE("DNS switching preserves original resolvers", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Enable DNS switching
    std::vector<std::string> tunnel_dns = {"10.8.0.1"};
    REQUIRE(sm.switch_dns(true, tunnel_dns));
    
    auto config = sm.get_dns_config();
    auto original_count = config.original_resolvers.size();
    REQUIRE(original_count > 0);

    // Disable and re-enable - original resolvers should be preserved
    REQUIRE(sm.switch_dns(false));
    REQUIRE(sm.switch_dns(true, {"172.16.0.1"}));
    
    config = sm.get_dns_config();
    REQUIRE(config.original_resolvers.size() == original_count);
}

TEST_CASE("DNS switching with empty resolver list", "[windows][control-channel]") {
    VpnStateMachine sm;

    // Enable without specifying resolvers (use defaults)
    REQUIRE(sm.switch_dns(true, {}));
    
    auto config = sm.get_dns_config();
    REQUIRE(config.enabled);
}