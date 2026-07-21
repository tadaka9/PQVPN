#include <gtest/gtest.h>
#include "../src/modules/network_module.hpp"
#include <asio.hpp>

TEST(UdpListenerTest, StartSuccess) {
    asio::io_context io_context;
    pqvpn::network::UdpListener listener(io_context, 12345);
    auto result = listener.start();
    EXPECT_TRUE(result.has_value());
}

TEST(UdpListenerTest, StartInvalidAddress) {
    asio::io_context io_context;
    pqvpn::network::UdpListener listener("127.0.0.1", 12345); // This doesn't match the constructor in header but let's see if we can force it via config
}
