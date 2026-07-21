#include <catch2/catch_test_macros.hpp>
#include "../src/modules/network_module.hpp"
#include <asio.hpp>

TEST_CASE("UDP Listener basic functionality", "[network]") {
    asio::io_context io_context;
    uint16_t test_port = 8888;

    SECTION("Successful start") {
        pqvpn::network::UdpListener listener(io_context, test_port);
        auto result = listener.start();

        REQUIRE(result.has_value());
        listener.stop();
    }

    SECTION("Failure on invalid port (if possible)") {
        // Using a privileged port might fail depending on OS/permissions,
        // but we can test the error handling logic by attempting to bind twice.
        pqvpn::network::UdpListener listener1(io_context, test_port);
        auto result1 = listener1.start();
        REQUIRE(result1.has_value());

        pqvpn::network::UdpListener listener2(io_context, test_port);
        auto result2 = listener2.start();
        // This should fail because the port is already bound by listener1
        REQUIRE(!result2.has_value());
        REQUIRE(result2.error() == pqvpn::network::NetworkError::BindFailed);

        listener1.stop();
    }
}

TEST_CASE("UDP listener receives a loopback datagram asynchronously", "[network]") {
    asio::io_context io_context;
    pqvpn::config::NetworkConfig config;
    config.bind_address = "127.0.0.1";
    config.port = 0;

    // Port zero is intentionally rejected by the production configuration,
    // so reserve an ephemeral port and then bind the listener to it.
    asio::ip::udp::socket reservation(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
    config.port = reservation.local_endpoint().port();
    reservation.close();

    pqvpn::network::UdpListener listener(io_context, config);
    std::vector<uint8_t> received;
    listener.set_receive_handler([&](std::vector<uint8_t> packet, const asio::ip::udp::endpoint&) {
        received = std::move(packet);
        io_context.stop();
    });
    REQUIRE(listener.start().has_value());

    asio::ip::udp::socket sender(io_context, asio::ip::udp::v4());
    const std::vector<uint8_t> message{1, 2, 3, 4};
    sender.send_to(asio::buffer(message), {
        asio::ip::make_address("127.0.0.1"), static_cast<uint16_t>(config.port)});

    asio::steady_timer deadline(io_context, std::chrono::seconds(1));
    deadline.async_wait([&](const asio::error_code&) { io_context.stop(); });
    io_context.run();
    listener.stop();
    REQUIRE(received == message);
}
