#include <catch2/catch_test_macros.hpp>

#include "node_module.hpp"

namespace {

struct SessionPair {
    asio::io_context io;
    pqvpn::PQVPNNode initiator{io};
    pqvpn::PQVPNNode responder{io};
    std::vector<uint8_t> initiator_id = std::vector<uint8_t>(32, 0x11);
    std::vector<uint8_t> responder_id = std::vector<uint8_t>(32, 0x22);
    asio::ip::udp::endpoint initiator_endpoint{asio::ip::make_address("127.0.0.1"), 9101};
    asio::ip::udp::endpoint responder_endpoint{asio::ip::make_address("127.0.0.1"), 9102};

    SessionPair() {
        const std::vector<uint8_t> x25519_secret(32, 0x33);
        const std::vector<uint8_t> ml_kem_secret(32, 0x44);
        const std::vector<uint8_t> transcript{'P', 'Q', 'V', 'P', 'N', '-', 'D', 'A', 'T', 'A'};
        initiator.establish_hybrid_session(
            responder_id, responder_endpoint, x25519_secret, ml_kem_secret, transcript, true);
        responder.establish_hybrid_session(
            initiator_id, initiator_endpoint, x25519_secret, ml_kem_secret, transcript, false);
    }

    void deliver(std::vector<uint8_t> datagram, const asio::ip::udp::endpoint& sender) {
        asio::co_spawn(io, responder.datagram_received(std::move(datagram), sender), asio::detached);
        io.run();
        io.restart();
    }
};

} // namespace

TEST_CASE("tunnel data plane authenticates and delivers a packet", "[tunnel][dataplane]") {
    SessionPair pair;
    const std::vector<uint8_t> packet{0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef};
    std::vector<std::vector<uint8_t>> delivered;
    pair.responder.set_tunnel_packet_handler(
        [&](std::vector<uint8_t> plaintext) { delivered.push_back(std::move(plaintext)); });

    const auto datagram = pair.initiator.build_tunnel_datagram(pair.responder_id, packet);
    REQUIRE(datagram);
    REQUIRE(datagram->at(0) == 1);
    REQUIRE(datagram->at(1) == pqvpn::PQVPNNode::TUNNEL_DATA_FRAME);
    pair.deliver(*datagram, pair.initiator_endpoint);

    REQUIRE(delivered == std::vector<std::vector<uint8_t>>{packet});
}

TEST_CASE("tunnel data plane rejects replay, tampering, and endpoint mismatch", "[tunnel][dataplane]") {
    SessionPair pair;
    const std::vector<uint8_t> packet{0x60, 0x00, 0x00, 0x00, 0xca, 0xfe};
    std::size_t deliveries = 0;
    pair.responder.set_tunnel_packet_handler(
        [&](std::vector<uint8_t>) { ++deliveries; });

    const auto first = pair.initiator.build_tunnel_datagram(pair.responder_id, packet);
    REQUIRE(first);
    pair.deliver(*first, pair.initiator_endpoint);
    REQUIRE(deliveries == 1);

    pair.deliver(*first, pair.initiator_endpoint);
    REQUIRE(deliveries == 1);

    const auto second = pair.initiator.build_tunnel_datagram(pair.responder_id, packet);
    REQUIRE(second);
    auto tampered = *second;
    tampered.back() ^= 0x80;
    pair.deliver(std::move(tampered), pair.initiator_endpoint);
    REQUIRE(deliveries == 1);

    const auto third = pair.initiator.build_tunnel_datagram(pair.responder_id, packet);
    REQUIRE(third);
    pair.deliver(*third, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9199));
    REQUIRE(deliveries == 1);
}

TEST_CASE("tunnel data plane refuses missing sessions and empty packets", "[tunnel][dataplane]") {
    asio::io_context io;
    pqvpn::PQVPNNode node(io);
    REQUIRE_FALSE(node.build_tunnel_datagram({1, 2, 3}, std::vector<uint8_t>{0x45}));
    REQUIRE_FALSE(node.build_tunnel_datagram({1, 2, 3}, std::vector<uint8_t>{}));
}
