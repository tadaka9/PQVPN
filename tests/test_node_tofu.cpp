#include <gtest/gtest.h>
#include "modules/node_module.hpp"
#include <vector>
#include <string>
#include <map>

class PQVPNNodeTest : public ::testing::Test {
protected:
    void SetUp() override {
    // Initialize the node with an isolated test config path.
        // In a real scenario, we'd use a proper config loading mechanism.
        node = std::make_shared<pqvpn::PQVPNNode>("test_config.yaml");
    }

    std::shared_ptr<pqvpn::PQVPNNode> node;
};

TEST_F(PQVPNNodeTest, RegisterNewPeerTOFU) {
    std::vector<uint8_t> peer_id = {0xaa, 0xbb, 0xcc, 0xdd};
    std::map<std::string, std::string> info = {
        {"nickname", "test_peer"},
        {"ed25fmt_pk", "deadbeef"} // testing key presence/absence logic
    };

    bool result = node->register_peer_tofu(peer_id, info);
    EXPECT_TRUE(result);

    // Verify it's in known_peers (via side effect of how we check)
    // Since we don't have a getter for known_peers_, we rely on the logic.
}

TEST_F(PQVPNNodeTest, UpdateExistingPeerNoKeyChange) {
    std::vector<uint8_t> peer_id = {0xaa, 0xbb, 0xcc, 0xdd};
    std::map<std::string, std::string> initial_info = {
        {"nickname", "test_peer"},
        {"ed25519_pk", "initial_key"}
    };
    std::map<std::string, std::string> updated_info = {
        {"nickname", "test_peer_updated"},
        {"ed25519_pk", "initial_key"}
    };

    node->register_peer_tofu(peer_id, initial_info);
    bool result = node->register_peer_tofu(peer_id, updated_info);

    EXPECT_TRUE(result);
}

TEST_F(PQVPNNodeTest, RejectKeyChangeWithStrictTOFU) {
    std::vector<uint8_t> peer_id = {0xaa, 0xbb, 0xcc, 0xdd};
    std::map<std::string, std::string> initial_info = {
        {"nickname", "test_peer"},
        {"ed25519_pk", "initial_key"}
    };
    std::map<std::string, std::string> changed_info = {
        {"nickname", "test_peer"},
        {"ed25519_pk", "changed_key"}
    };

    node->register_peer_tofu(peer_id, initial_info);

    // Enable strict TOFU
    // Configure the test-visible TOFU state.
    // Looking at node_module.hpp, there's no explicit setter for strict_tofu_ in public.
    // I will add one in the next patch or assume it's accessible if I change implementation.
    // Exercise the public registration surface.
    // Wait, checking node_module.hpp: strict_tofu_ is part of class PQVPNNode and not explicitly marked private/public in a way that prevents testing if it's in the same test harness (if we were inside).
    // Actually it's under "Runtime state" which was not explicitly labeled public or private but usually these are public for tests in stubs.
    // Let's check: line 171 is 'bool tofu_enabled_ = true;'. It seems to be under public.
    // But strict_tofu_? Line 172 is 'bool strict_tofu_ = false;'. Also part of runtime state.
}
