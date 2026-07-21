#include <gtest/gtest.h>
#include "modules/node_module.hpp"
#include <asio.hpp>
#include <memory>
#include <vector>
#include <string>
#include <map>

class PQVPNNodeTest : public ::testing::Test {
protected:
    void SetUp() override {
        io_ctx = std::make_shared<asio::io_context>();
        node = std::make_shared<pqvpn::PQVPNNode>(*io_ctx, "test_config.yaml");
    }

    std::shared_ptr<asio::io_context> io_ctx;
    std::shared_ptr<pqvpn::PQVPNNode> node;
};

TEST_F(PQVPNNodeTest, RegisterNewPeerTOFU) {
    std::vector<uint8_t> peer_id = {0xaa, 0xbb, 0xcc, 0xdd};
    std::map<std::string, std::string> info = {
        {"nickname", "test_peer"},
        {"ed25519_pk", "deadbeef"}
    };

    bool result = node->register_peer_tofu(peer_id, info);
    EXPECT_TRUE(result);
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
