// Unit tests for WindowsOwnTunnel adapter backend (Phase 2 user-mode component).
// Tests lifecycle operations: open, write, close, is_open, describe.
// Note: Actual device I/O requires the kernel driver to be loaded; these tests
// verify the user-mode logic and error handling paths.

#include <catch2/catch_test_macros.hpp>
#include "platform/windows_own_tunnel.hpp"

using namespace pqvpn::platform;

TEST_CASE("WindowsOwnTunnel lifecycle", "[windows][own-tunnel]") {
    WindowsOwnTunnel tunnel;

    // Initially closed
    REQUIRE(!tunnel.is_open());

    // Describe works even when closed
    auto desc = tunnel.describe();
    REQUIRE(desc.find("PQVPN tunnel driver") != std::string::npos);

    // Open without device should fail gracefully (no crash)
    bool opened = tunnel.open([](WindowsOwnTunnel::Packet pkt) {
        // Inbound handler - not called in this test
    });
    // On a system without the driver loaded, open fails
    if (!opened) {
        REQUIRE(!tunnel.is_open());
    } else {
        // If it opened (driver is loaded), verify state and close cleanly
        REQUIRE(tunnel.is_open());
        tunnel.close();
        REQUIRE(!tunnel.is_open());
    }

    // Close is idempotent
    tunnel.close();
}

TEST_CASE("WindowsOwnTunnel write when closed", "[windows][own-tunnel]") {
    WindowsOwnTunnel tunnel;

    // Write to closed adapter should return false, not crash
    std::vector<uint8_t> packet = {0x45, 0x00, 0x00, 0x3c}; // Minimal IPv4 header
    bool written = tunnel.write(packet);
    REQUIRE(!written);
}

TEST_CASE("WindowsOwnTunnel write invalid sizes", "[windows][own-tunnel]") {
    WindowsOwnTunnel tunnel;

    // Empty packet is invalid
    std::vector<uint8_t> empty;
    REQUIRE(!tunnel.write(empty));

    // Oversized packet (>65536 bytes) is invalid
    std::vector<uint8_t> huge(70000, 0x42);
    REQUIRE(!tunnel.write(huge));
}

TEST_CASE("WindowsOwnTunnel custom device name", "[windows][own-tunnel]") {
    WindowsOwnTunnel tunnel("\\\\.\\PQVPN_TUN_CUSTOM");

    auto desc = tunnel.describe();
    REQUIRE(desc.find("PQVPN_TUN_CUSTOM") != std::string::npos);
}