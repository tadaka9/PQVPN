#include <catch2/catch_test_macros.hpp>
#include "node_module.hpp"
#include "udp_protocol.hpp"

TEST_CASE("UDP protocol schedules node validation and retains its lifetime", "[node][network]") {
    asio::io_context io;
    auto node = std::make_shared<pqvpn::PQVPNNode>(io);
    std::weak_ptr<pqvpn::PQVPNNode> lifetime = node;
    pqvpn::UDPProtocol protocol(node);
    const asio::ip::udp::endpoint sender(asio::ip::make_address("127.0.0.1"), 9999);
    // The node rejects this truncated outer frame inside its coroutine.
    protocol.datagram_received({}, {1, pqvpn::PQVPNNode::HELLO_FRAME}, sender);
    node.reset();
    REQUIRE_FALSE(lifetime.expired());
    REQUIRE(io.run() > 0);
    REQUIRE(lifetime.expired());
}

TEST_CASE("UDP protocol ignores transport errors and expired nodes", "[node][network]") {
    asio::io_context io;
    auto node = std::make_shared<pqvpn::PQVPNNode>(io);
    pqvpn::UDPProtocol protocol(node);
    const asio::ip::udp::endpoint sender(asio::ip::make_address("127.0.0.1"), 9999);
    protocol.datagram_received(asio::error::operation_aborted, {1, 0}, sender);
    REQUIRE(io.poll() == 0);
    io.restart();
    node.reset();
    protocol.datagram_received({}, {1, 0}, sender);
    REQUIRE(io.poll() == 0);
}

TEST_CASE("UDP protocol attaches and detaches the node transport", "[node][network]") {
    asio::io_context io;
    auto node = std::make_shared<pqvpn::PQVPNNode>(io);
    pqvpn::UDPProtocol protocol(node);
    asio::ip::udp::socket socket(io);
    protocol.connection_made(socket);
    REQUIRE(node->transport == &socket);
    protocol.connection_lost({});
    REQUIRE(node->transport == nullptr);
}

TEST_CASE("UDP protocol preserves authenticated outer frames", "[node][network]") {
    asio::io_context io;
    pqvpn::PQVPNNode initiator(io);
    auto responder = std::make_shared<pqvpn::PQVPNNode>(io);
    const std::vector<uint8_t> initiator_id(32, 0x11), responder_id(32, 0x22);
    const std::vector<uint8_t> classical(32, 0x33), post_quantum(32, 0x44);
    const std::vector<uint8_t> transcript{'U', 'D', 'P'};
    const asio::ip::udp::endpoint source(asio::ip::make_address("127.0.0.1"), 9101);
    const asio::ip::udp::endpoint destination(asio::ip::make_address("127.0.0.1"), 9102);
    initiator.establish_hybrid_session(responder_id, destination,
        classical, post_quantum, transcript, true);
    responder->establish_hybrid_session(initiator_id, source,
        classical, post_quantum, transcript, false);
    const std::vector<uint8_t> packet{0x45, 0, 0, 20, 0xde, 0xad};
    std::vector<uint8_t> delivered;
    responder->set_tunnel_packet_handler(
        [&](std::vector<uint8_t> plaintext, const std::vector<uint8_t>& peer) {
            REQUIRE(peer == initiator_id);
            delivered = std::move(plaintext);
        });
    auto frame = initiator.build_tunnel_datagram(responder_id, packet);
    REQUIRE(frame);
    pqvpn::UDPProtocol protocol(responder);
    protocol.datagram_received({}, *frame, source);
    io.run();
    REQUIRE(delivered == packet);
    delivered.clear();
    io.restart();
    protocol.datagram_received({}, *frame, source);
    io.run();
    REQUIRE(delivered.empty());
}
