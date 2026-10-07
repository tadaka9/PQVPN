#include <catch2/catch_test_macros.hpp>
#include "ml_traffic_shaper.hpp"
#include "external_transport.hpp"

TEST_CASE("Shaper learns local workload and preserves bounded authenticated envelopes") {
    using namespace pqvpn::traffic;
    TrafficModel model;
    auto now = TrafficModel::Clock::now();
    for (int i = 0; i < 200; ++i) model.observe(1200, now + std::chrono::milliseconds(i * 40));
    REQUIRE(model.predicted_size() > 1100);
    REQUIRE(model.predicted_gap_ms() > 35);
    asio::io_context io;
    auto shaper = std::make_shared<MLTrafficShaper>(io, ShapingConfig{});
    std::vector<uint8_t> packet(100, 42);
    auto padded = shaper->pad(packet);
    REQUIRE(padded.size() > packet.size());
    REQUIRE(MLTrafficShaper::unpad(padded) == packet);
    padded[0] = 2;
    REQUIRE_FALSE(MLTrafficShaper::unpad(padded));
    REQUIRE_THROWS(shaper->pad(std::vector<uint8_t>(65507)));
}

TEST_CASE("Shaper queues in order, rejects overflow and stops without bypass") {
    using namespace pqvpn::traffic;
    asio::io_context io;
    ShapingConfig config;
    config.max_queue_packets = 2;
    config.max_delay_ms = 0;
    auto shaper = std::make_shared<MLTrafficShaper>(io, config);
    std::vector<int> delivered;
    auto send = [&](const auto& packet) {
        if (packet.front() != 0) delivered.push_back(packet.front());
        return packet.front() != 0;
    };
    REQUIRE(shaper->enqueue({1}, 1, send));
    REQUIRE(shaper->enqueue({2}, 1, send));
    REQUIRE_FALSE(shaper->enqueue({3}, 1, send));
    io.run();
    REQUIRE(delivered == std::vector<int>{1, 2});
    REQUIRE(shaper->sent_packets() == 2);
    REQUIRE(shaper->dropped_packets() == 1);
    io.restart();
    REQUIRE(shaper->enqueue({0}, 1, send));
    io.run();
    REQUIRE(delivered.size() == 2);
    REQUIRE(shaper->dropped_packets() == 2);
    io.restart();
    REQUIRE(shaper->enqueue({4}, 1, send));
    shaper->stop();
    io.run();
    REQUIRE(delivered.size() == 2);
    REQUIRE(shaper->queued_bytes() == 0);
    REQUIRE_FALSE(shaper->enqueue({5}, 1, send));
}

TEST_CASE("External UDP transport rejects nonlocal endpoints and TCP engines") {
    pqvpn::ExternalTransport external{"udp2raw", "127.0.0.1", 9091};
    REQUIRE(external.endpoint().port() == 9091);
    external.host = "192.0.2.1";
    REQUIRE_THROWS(external.endpoint());
    external.host = "127.0.0.1";
    external.engine = "obfs4";
    REQUIRE_THROWS(external.endpoint());
    asio::io_context io;
    asio::ip::udp::socket socket(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
    asio::ip::udp::endpoint endpoint(asio::ip::make_address("127.0.0.1"), 9091);
    REQUIRE(pqvpn::transport_allows(&socket, endpoint));
    socket.connect(endpoint);
    REQUIRE(pqvpn::transport_allows(&socket, endpoint));
    REQUIRE_FALSE(pqvpn::transport_allows(&socket, {endpoint.address(), 9092}));
}
