#include <gtest/gtest.h>
#include "PQVPNNode.h"
#include <boost/asio.hpp>
#include <memory>
#include <vector>

class PQVPNNodeTest : public ::testing::Test {
protected:
    void SetUp() override {
        io_context = std::make_shared<boost::asio::io_context>();
        node = std::make_shared<pqvpn::PQVPNNode>(*io_context, "test_config.yaml");
    }

    std::shared_ptr<boost::asio::io_context> io_context;
    std::shared_ptr<pqvpn::PQVPNNode> node;
};

TEST_F(PQVPNNodeTest, SendToIPv4Address) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    std::string host = "127.0.0.1";
    int port = 5000;

    bool result = node->send_to(data, host, port);
    SUCCEED();
}
