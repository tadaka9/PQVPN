#include <gtest/gtest.h>
#include "PQVPNNode.h"
#include <vector>

class MockTransport : public Transport {
public:
    void sendto(const std::vector<uint8_t>& data, const std::string& host, int port) override {
        // Mock implementation
    }
};

TEST(PQVPNNodeTest, HandleS1Basic) {
    asio::io_context io_ctx;
    pqvpn::PQVPNNode node(io_ctx, "test_config.yaml");
    // Create the empty payload boundary case.
    std::vector<uint8_t> payload = {};
    std::string addr = "127.0.0.1";
    int port = 5000;

    // This test just verifies that the function can be called without crashing
    node.handle_s1(payload, addr, port);

    // If we get here without exception, the test passes
    SUCCEED();
}

TEST(PQVPNNodeTest, HandleS1WithPayload) {
    asio::io_context io_ctx;
    pqvpn::PQVPNNode node(io_ctx, "test_config.yaml");
    // Create the empty JSON payload boundary case.
    std::vector<uint8_t> payload = {0x7b, 0x7d}; // "{}" in bytes
    std::string addr = "127.0.0.1";
    int port = 5000;

    // This should not crash even with basic JSON input
    node.handle_s1(payload, addr, port);

    SUCCEED();
}
