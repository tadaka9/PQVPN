#include <catch2/catch_test_macros.hpp>
#include "strangenet.hpp"
#include "node_module.hpp"

using namespace pqvpn::strangenet;

TEST_CASE("StrangeNet messages round-trip with bounded metadata", "[strangenet]") {
    const Message sent{"riemann-lab", "peer-alice", 7, 1700000000123ULL, "hello from the other sheet"};
    const auto wire = encode(sent);
    REQUIRE(wire.has_value());
    const auto received = decode(*wire);
    REQUIRE(received.has_value());
    CHECK(received->room == sent.room);
    CHECK(received->sender == sent.sender);
    CHECK(received->sequence == sent.sequence);
    CHECK(received->text == sent.text);
}

TEST_CASE("StrangeNet rejects malformed and replayed messages", "[strangenet]") {
    Message message{"room", "peer", 1, 1, "hello"};
    auto wire = encode(message);
    REQUIRE(wire.has_value());
    wire->pop_back();
    CHECK_FALSE(decode(*wire).has_value());
    ReplayGuard guard;
    CHECK(guard.accept(message));
    CHECK_FALSE(guard.accept(message));
    message.sequence = 2;
    CHECK(guard.accept(message));
    guard.leave_room("room");
    CHECK(guard.accept(message));
}

TEST_CASE("StrangeNet travels through an authenticated PQVPN session", "[strangenet][tunnel]") {
    asio::io_context io;
    pqvpn::PQVPNNode alice{io}, bob{io};
    const std::vector<std::uint8_t> alice_id(32, 0x41), bob_id(32, 0x42);
    const asio::ip::udp::endpoint alice_endpoint{asio::ip::make_address("127.0.0.1"), 9201};
    const asio::ip::udp::endpoint bob_endpoint{asio::ip::make_address("127.0.0.1"), 9202};
    const std::vector<std::uint8_t> x25519(32, 0x33), ml_kem(32, 0x44);
    const std::vector<std::uint8_t> transcript{'S','T','R','A','N','G','E','N','E','T'};
    alice.set_my_id(alice_id);
    bob.set_my_id(bob_id);
    REQUIRE(alice.establish_hybrid_session(bob_id, bob_endpoint, x25519, ml_kem, transcript, true));
    REQUIRE(bob.establish_hybrid_session(alice_id, alice_endpoint, x25519, ml_kem, transcript, false));

    std::vector<Message> received;
    bob.set_strangenet_handler([&](const Message& message, const std::vector<std::uint8_t>& peer) {
        CHECK(peer == alice_id);
        received.push_back(message);
    });
    const auto frame = alice.build_strangenet_datagram(bob_id, "riemann-lab", 1, 42, "hello Bob");
    REQUIRE(frame.has_value());
    CHECK(frame->at(1) == pqvpn::PQVPNNode::STRANGENET_FRAME);
    asio::co_spawn(io, bob.datagram_received(*frame, alice_endpoint), asio::detached);
    io.run();
    REQUIRE(received.size() == 1);
    CHECK(received.front().room == "riemann-lab");
    CHECK(received.front().text == "hello Bob");

    io.restart();
    asio::co_spawn(io, bob.datagram_received(*frame, alice_endpoint), asio::detached);
    io.run();
    CHECK(received.size() == 1);
}
