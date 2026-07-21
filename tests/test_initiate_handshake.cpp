#include <gtest/gtest.h>
#include "PQVPNNode.h"
#include <vector>

class MockTransport : public Transport {
public:
    void sendto(const std::vector<uint8_t>& data, const std::string& host, int port) override {
        // Mock implementation
    }
};

TEST(PQVPNNodeTest, InitiateHandshakeBasic) {
        asio::io_context io_ctx;\n        pqvpn::PQVPNNode node(io_ctx, \"test_config.yaml\");

    // Create a mock peer info
    PeerInfo pinfo;
    pinfo.nickname = "test_peer";
    pinfo.kyber_pk = {0x01, 0x02, 0x03, 0x04};

    // This test just verifies that the function can be called without crashing
    node.initiate_handshake(pinfo, "127.0.0.1", 5000);

    // If we get here without exception, the test passes
    SUCCEED();
}

TEST(PQVPNNodeTest, InitiateHandshakeWithEmptyPeerInfo) {
        asio::io_context io_ctx;\n        pqvpn::PQVPNNode node(io_ctx, \"test_config.yaml\");

    // Test with empty peer info
    PeerInfo pinfo;

    // This should not crash
    node.initiate_handshake(pinfo, "127.0.0.1", 5000);

    SUCCEED();
}
