#include <catch2/catch_test_macros.hpp>
#include "node_module.hpp"

TEST_CASE("hybrid session installs complementary directional keys", "[crypto][hybrid][session]") {
    asio::io_context io;
    pqvpn::PQVPNNode initiator(io);
    pqvpn::PQVPNNode responder(io);
    const std::vector<uint8_t> initiator_id(32, 0x01);
    const std::vector<uint8_t> responder_id(32, 0x02);
    const std::vector<uint8_t> x25519_secret(32, 0x33);
    const std::vector<uint8_t> ml_kem_secret(32, 0x44);
    const std::vector<uint8_t> transcript{'P', 'Q', 'V', 'P', 'N', '-', 'H', 'S', '1'};
    const asio::ip::udp::endpoint initiator_endpoint(asio::ip::make_address("127.0.0.1"), 9001);
    const asio::ip::udp::endpoint responder_endpoint(asio::ip::make_address("127.0.0.1"), 9002);

    const auto initiator_session = initiator.establish_hybrid_session(
        responder_id, responder_endpoint, x25519_secret, ml_kem_secret, transcript, true);
    const auto responder_session = responder.establish_hybrid_session(
        initiator_id, initiator_endpoint, x25519_secret, ml_kem_secret, transcript, false);

    REQUIRE(initiator_session->state == pqvpn::PQVPNNode::SessionState::ESTABLISHED);
    REQUIRE(initiator_session->aead_send_key == responder_session->aead_recv_key);
    REQUIRE(initiator_session->aead_recv_key == responder_session->aead_send_key);
    REQUIRE(initiator_session->session_id == responder_session->session_id);
    REQUIRE(initiator_session->session_iv == responder_session->session_iv);
    REQUIRE(initiator_session->aead_send_key != initiator_session->aead_recv_key);
    REQUIRE(initiator.sessions_by_peer_id.at(responder_id) == initiator_session);
}

TEST_CASE("hybrid session rejects missing security inputs", "[crypto][hybrid][session]") {
    asio::io_context io;
    pqvpn::PQVPNNode node(io);
    const asio::ip::udp::endpoint remote(asio::ip::make_address("127.0.0.1"), 9002);
    REQUIRE_THROWS_AS(node.establish_hybrid_session(
        {1}, remote, {}, {2}, {3}, true), std::invalid_argument);
}
