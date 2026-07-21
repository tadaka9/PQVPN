#include <gtest/gtest.h>
#include "src/modules/node_module.hpp"
#include <map>

namespace pqvpn {

class TestNode : public PQVPNNode {
public:
    using PQVPNNode::PQVPNNode;

    // Expose the method for testing
    std::optional<std::map<std::string, std::string>> find_known_peer_by_pubkeys(const std::map<std::string, std::string>& j) {
        return PQVPNNode::find_known_peer_by_pubkeys(j);
    }
};

TEST(NodeTest, FindKnownPeerByPubKeys) {
    // Create a test node
    TestNode node("test_config.yaml");

    // Add some known peers to the TOFU store
    std::map<std::string, std::string> peer1_info = {
        {"ed25519_pk", "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"},
        {"nickname", "TestPeer1"}
    };

    // Add to our known peers store (simplified for test)
    node.known_peers_[peer1_info["ed25519_pk"]] = peer1_info;

    // Test finding a peer
    std::map<std::string, std::string> payload = {
        {"ed25519_pk", "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"},
        {"nickname", "TestPayload"}
    };

    auto result = node.find_known_peer_by_pubkeys(payload);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->at("nickname"), "TestPeer1");
}

TEST(NodeTest, FindKnownPeerNoMatch) {
    // Create a test node
    TestNode node("test_config.yaml");

    // Add some known peers to the TOFU store
    std::map<std::string, std::string> peer1_info = {
        {"ed25519_pk", "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"},
        {"nickname", "TestPeer1"}
    };

    // Add to our known peers store (simplified for test)
    node.known_peers_[peer1_info["ed25519_pk"]] = peer1_info;

    // Test with a payload that doesn't match
    std::map<std::string, std::string> payload = {
        {"ed25519_pk", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
        {"nickname", "TestPayload"}
    };

    auto result = node.find_known_peer_by_pubkeys(payload);
    ASSERT_FALSE(result.has_value());
}

TEST(NodeTest, FindKnownPeerByPubKeysCaseInsensitive) {
    // Create a test node
    TestNode node("test_config.yaml");

    // Add some known peers with uppercase hex keys
    std::map<std::string, std::string> peer1_info = {
        {"ed25519_pk", "A1B2C3D4E5F67890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"},
        {"nickname", "TestPeerUppercase"}
    };

    // Add to our known peers store (simplified for test)
    node.known_peers_[peer1_info["ed25519_pk"]] = peer1_info;

    // Test with lowercase payload - should match due to normalization
    std::map<std::string, std::string> payload = {
        {"ed25519_pk", "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"},
        {"nickname", "TestPayload"}
    };

    auto result = node.find_known_peer_by_pubkeys(payload);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->at("nickname"), "TestPeerUppercase");
}

TEST(NodeTest, FindKnownPeerByPubKeysWithMultipleKeyTypes) {
    // Create a test node
    TestNode node("test_config.yaml");

    // Add some known peers with various key types
    std::map<std::string, std::string> peer1_info = {
        {"ed25519_pk", "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"},
        {"brainpoolP512r1_pk", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
        {"nickname", "TestPeerMultipleKeys"}
    };

    // Add to our known peers store (simplified for test)
    node.known_peers_[peer1_info["ed25519_pk"]] = peer1_info;

    // Test with payload matching brainpool key instead of ed25519
    std::map<std::string, std::string> payload = {
        {"brainpoolP512r1_pk", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
        {"nickname", "TestPayload"}
    };

    auto result = node.find_known_peer_by_pubkeys(payload);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->at("nickname"), "TestPeerMultipleKeys");
}

TEST(NodeTest, FindKnownPeerByPubKeysWithBase64) {
    // Create a test node
    TestNode node("test_config.yaml");

    // Add some known peers with base64 encoded keys (will be converted to hex)
    std::map<std::string, std::string> peer1_info = {
        {"ed25519_pk", "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"},
        {"nickname", "TestPeerBase64"}
    };

    // Add to our known peers store (simplified for test)
    node.known_peers_[peer1_info["ed25519_pk"]] = peer1_info;

    // Test with base64 payload - should match after conversion
    std::map<std::string, std::string> payload = {
        {"ed25519_pk", "obLD1OX2eJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA="},
        {"nickname", "TestPayload"}
    };

    auto result = node.find_known_peer_by_pubkeys(payload);
    // This should work since our implementation properly converts base64 to hex
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->at("nickname"), "TestPeerBase64");
}

} // namespace pqvpn
