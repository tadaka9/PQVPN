#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include "src/modules/node_module.hpp"

// Test that load_known_peers compiles and can be called without crashing
TEST(LoadKnownPeersTest, CompileAndExecute) {
    // Create a temporary config file for testing
    std::ofstream tmp_config("test_config.toml");
    tmp_config << "[network]\nport = 9001\nhost = \"127.0.0.1\"\n\n[security]\n";
    tmp_config.close();

    pqvpn::PQVPNNode node("test_config.toml");

    // Should not crash
    node.load_known_peers();

    // Clean up test files
    std::filesystem::remove("test_config.toml");
}

// Test with some existing peers data
TEST(LoadKnownPeersTest, WithPeerData) {
    std::ofstream tmp_config("test_config2.toml");
    tmp_config << "[network]\nport = 9001\nhost = \"127.0.0.1\"\n\n[security]\nknown_peers_file = \"test_known_peers.yaml\"\n";
    tmp_config.close();

    // Create a mock known peers file with YAML structure
    std::ofstream peer_file("test_known_peers.yaml");
    peer_file << "peers:\n  abcdef1234567890:\n    ed25519_pk: \"test_key_1\"\n    nickname: \"test_peer_1\"\n";
    peer_file.close();

    pqvpn::PQVPNNode node("test_config2.toml");

    // Should not crash
    node.load_known_peers();

    // Clean up test files
    std::filesystem::remove("test_config2.toml");
    std::filesystem::remove("test_known_peers.yaml");
}