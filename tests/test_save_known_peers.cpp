#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include "src/modules/node_module.hpp"

// Test that save_known_peers compiles and can be called without crashing
TEST(SaveKnownPeersTest, CompileAndExecute) {
    // Create a temporary config file for testing
    std::ofstream tmp_config("test_config.toml");
    tmp_config << "[network]\nport = 9001\nhost = \"127.0.0.1\"\n\n[security]\n";
    tmp_config.close();

    pqvpn::PQVPNNode node("test_config.toml");

    // Should not crash
    node.save_known_peers();

    // Clean up test files
    std::filesystem::remove("test_config.toml");
}

// Test with some peers data
TEST(SaveKnownPeersTest, WithPeerData) {
    std::ofstream tmp_config("test_config2.toml");
    tmp_config << "[network]\nport = 9001\nhost = \"127.0.0.1\"\n\n[security]\nknown_peers_file = \"test_known_peers.yaml\"\n";
    tmp_config.close();

    pqvpn::PQVPNNode node("test_config2.toml");

    // Add some test peer data
    std::map<std::string, std::string> peer_info;
    peer_info["ed25519_pk"] = "test_key_1";
    peer_info["nickname"] = "test_peer_1";

    node.register_peer_tofu({0x01, 0x02, 0x03}, peer_info);

    // Should not crash
    node.save_known_peers();

    // Clean up test files
    std::filesystem::remove("test_config2.toml");
    std::filesystem::remove("test_known_peers.yaml");
}