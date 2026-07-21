#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <asio.hpp>
#include "modules/node_module.hpp"

TEST(PQVPNNodeTest, SendOnionEmptyPathReturnsFalse) {
    asio::io_context io_context;
    pqvpn::PQVPNNode node(io_context);
    std::vector<std::vector<uint8_t>> path;
    std::vector<uint8_t> inner_frame = {0x01, 0x02};

    asio::co_spawn(io_context, node.send_onion(path, inner_frame), [](std::exception_ptr e, bool result) {
        EXPECT_FALSE(result);
    });
    io_context.run();
}

TEST(PQVPNNodeTest, SendOnionNoSessionReturnsFalse) {
    asio::io_context io_context;
    pqvpn::PQVPNNode node(io_context);
    std::vector<std::vector<uint8_t>> path = {{0x01, 0x02, 0x03, 0x04}};
    std::vector<uint8_t> inner_frame = {0x01, 0x02};

    asio::co_spawn(io_context, node.send_onion(path, inner_frame), [](std::exception_ptr e, bool result) {
        EXPECT_FALSE(result);
    });
    io_context.run();
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
