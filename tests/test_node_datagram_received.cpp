#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <cstdint>
#include "../src/modules/node_module.hpp"
#include <asio.hpp>
#include <memory>

TEST_CASE("PQVPNNode::datagram_received behavior", "[node][network]") {
    asio::io_context io_ctx;
    pqvpn::PQVPNNode node(io_ctx);

    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    asio::ip::udp::endpoint addr(asio::ip::make_address("127.0.0.1"), 9999);

    SECTION("Successful datagram processing does not throw") {
        // Malformed short datagrams are dropped without throwing.
        // We use an asio executor to run the coroutine.
        asio::co_spawn(io_ctx, node.datagram_received(data, addr), asio::use_future);

        REQUIRE_NOTHROW(io_ctx.run());
    }

    SECTION("Error in _process_outer_datagram is caught and logged") {
        std::vector<uint8_t> error_data = {0xFF, 0x00};
        io_ctx.restart();
        asio::co_spawn(io_ctx, node.datagram_received(error_data, addr), asio::use_future);
        REQUIRE_NOTHROW(io_ctx.run());
    }
}
