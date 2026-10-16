#include <catch2/catch_test_macros.hpp>
#include "strangenet.hpp"
#include "node_module.hpp"

using namespace pqvpn::strangenet;

TEST_CASE("StrangeNet messages round-trip with bounded metadata", "[strangenet]") {
    const Message sent{"riemann-lab", "peer-alice", 7, 1700000000123ULL, "hello 👋 from the other sheet"};
    const auto wire = encode(sent);
    REQUIRE(wire.has_value());
    const auto received = decode(*wire);
    REQUIRE(received.has_value());
    CHECK(received->room == sent.room);
    CHECK(received->sender == sent.sender);
    CHECK(received->sequence == sent.sequence);
    CHECK(received->text == sent.text);
}

TEST_CASE("StrangeNet carries delivery receipts, stickers and reactions", "[strangenet]") {
    const Message receipt{"mainnet", "peer-bob", 8, 1700000000124ULL, {}, Kind::Acknowledgement, 7};
    const Message sticker{"mainnet", "peer-bob", 9, 1700000000125ULL,
        R"({"emoji":"🚀","caption":"PQ ready","color":"#5432c9"})", Kind::Sticker};
    const Message reaction{"mainnet", "peer-alice", 10, 1700000000126ULL, "❤️", Kind::Reaction, 9};
    for (const auto& sent : {receipt, sticker, reaction}) {
        const auto wire = encode(sent); REQUIRE(wire.has_value());
        const auto received = decode(*wire); REQUIRE(received.has_value());
        CHECK(received->kind == sent.kind);
        CHECK(received->reply_to == sent.reply_to);
        CHECK(received->text == sent.text);
    }
}

TEST_CASE("StrangeNet rejects invalid UTF-8 and malformed acknowledgements", "[strangenet]") {
    Message invalid{"mainnet", "peer", 1, 1, std::string{"\xF0\x28\x8C\x28", 4}};
    CHECK_FALSE(encode(invalid).has_value());
    Message bad_ack{"mainnet", "peer", 2, 2, {}, Kind::Acknowledgement, 0};
    CHECK_FALSE(encode(bad_ack).has_value());
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
    message.sequence = 3;
    CHECK(guard.accept(message));
    message.sequence = 2;
    CHECK(guard.accept(message)); // bounded UDP reordering is accepted once
    CHECK_FALSE(guard.accept(message));
    guard.leave_room("room");
    CHECK(guard.accept(message));
}

TEST_CASE("StrangeNet bounds replay state", "[strangenet][hardening]") {
    ReplayGuard guard;
    for (std::size_t index = 0; index < kMaxReplayStreams; ++index) {
        Message message{"room-" + std::to_string(index), "peer", 1, 1, "hello"};
        REQUIRE(guard.accept(message));
    }
    CHECK_FALSE(guard.accept(Message{"overflow", "peer", 1, 1, "blocked"}));
    guard.leave_room("room-0");
    CHECK(guard.accept(Message{"replacement", "peer", 1, 1, "accepted"}));
}

TEST_CASE("StrangeNet antiflood limits one authenticated sender", "[strangenet][hardening]") {
    FloodGuard guard;
    Message message{"mainnet", "peer-alice", 1, 1, "x"};
    for (std::uint64_t sequence = 1; sequence <= 8; ++sequence) {
        message.sequence = sequence;
        message.room = sequence % 2 == 0 ? "mainnet" : "another-room";
        CHECK(guard.accept(message, 1000).allowed);
    }
    const auto limited = guard.accept(message, 1000);
    CHECK_FALSE(limited.allowed);
    CHECK(limited.retry_after_ms == 500);
    CHECK(guard.accept(message, 1500).allowed);
}

TEST_CASE("StrangeNet antiflood bounds a large room in aggregate", "[strangenet][hardening]") {
    FloodGuard guard;
    for (std::size_t index = 0; index < 128; ++index) {
        const Message message{"mainnet", "peer-" + std::to_string(index), 1, 1, "x"};
        REQUIRE(guard.accept(message, 1000).allowed);
    }
    const Message overflow{"mainnet", "peer-overflow", 1, 1, "x"};
    const auto limited = guard.accept(overflow, 1000);
    CHECK_FALSE(limited.allowed);
    CHECK(limited.retry_after_ms > 0);
    CHECK(limited.retry_after_ms <= 32);
    CHECK(guard.accept(overflow, 1032).allowed);
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

TEST_CASE("StrangeNet group delivery fails closed unless every member is ready", "[strangenet][group]") {
    asio::io_context io;
    pqvpn::PQVPNNode alice{io};
    alice.set_my_id(std::vector<std::uint8_t>(32, 0x41));
    const std::vector<std::vector<std::uint8_t>> group{
        std::vector<std::uint8_t>(32, 0x42), std::vector<std::uint8_t>(32, 0x43)};
    CHECK(alice.send_strangenet_group(group, "three-person-room", 1, 42, "hello") == 0);
    CHECK(alice.send_strangenet_group({group.front()}, "too-small", 2, 43, "blocked") == 0);
}
