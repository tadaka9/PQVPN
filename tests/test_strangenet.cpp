#include <catch2/catch_test_macros.hpp>
#include "strangenet.hpp"
#include "node_module.hpp"
#include "woockie.hpp"

using namespace pqvpn::strangenet;

TEST_CASE("Woockie combines a canonical peer identity with a safe resource path", "[woockie]") {
    const std::string peer(64, 'A');
    const auto address = pqvpn::woockie::parse(
        "woockie://" + peer + "/strangenet/mainnet/friends/poetry");
    REQUIRE(address.has_value());
    CHECK(address->peer_id == std::string(64, 'a'));
    CHECK(address->service == "strangenet");
    CHECK(address->resource == "mainnet/friends/poetry");
    CHECK(pqvpn::woockie::canonical(*address) ==
        "woockie://" + std::string(64, 'a') + "/strangenet/mainnet/friends/poetry");
}

TEST_CASE("Woockie rejects web ambiguity and unregistered capabilities", "[woockie][hardening]") {
    const std::string peer(64, '1');
    CHECK_FALSE(pqvpn::woockie::parse("https://" + peer + "/strangenet/room"));
    CHECK_FALSE(pqvpn::woockie::parse("woockie://user@" + peer + "/strangenet/room"));
    CHECK_FALSE(pqvpn::woockie::parse("woockie://" + peer + "/strangenet/../secret"));
    CHECK_FALSE(pqvpn::woockie::parse("woockie://" + peer + "/shell/run"));
    CHECK_FALSE(pqvpn::woockie::parse("woockie://" + peer + "/asgard/object?token=secret"));
}

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

TEST_CASE("StrangeNet text can reply to a prior message", "[strangenet][reply]") {
    const Message reply{"mainnet/friends", "peer-bob", 11, 1700000000127ULL,
        "I agree", Kind::Text, 7};
    const auto wire = encode(reply);
    REQUIRE(wire.has_value());
    const auto decoded = decode(*wire);
    REQUIRE(decoded.has_value());
    CHECK(decoded->kind == Kind::Text);
    CHECK(decoded->reply_to == 7);
}

TEST_CASE("StrangeNet carries bounded voice chunks but no arbitrary media kind", "[strangenet][voice]") {
    const Message voice{"mainnet/lounge", "peer-alice", 11, 1700000000127ULL,
        R"({"rate":16000,"channels":1,"sample":"s16","audio":"AAECAwQ="})", Kind::Voice};
    const auto wire = encode(voice);
    REQUIRE(wire.has_value());
    const auto decoded = decode(*wire);
    REQUIRE(decoded.has_value());
    CHECK(decoded->kind == Kind::Voice);

    const Message direct{"@direct", "peer-alice", 12, 1700000000128ULL, "private hello", Kind::DirectText};
    const auto direct_wire = encode(direct);
    REQUIRE(direct_wire.has_value());
    const auto direct_decoded = decode(*direct_wire);
    REQUIRE(direct_decoded.has_value());
    CHECK(direct_decoded->kind == Kind::DirectText);
    CHECK(direct_decoded->room == "@direct");
    CHECK(direct_decoded->text == "private hello");
    CHECK(decoded->room == "mainnet/lounge");
    CHECK(decoded->text == voice.text);

    Message forbidden = voice;
    forbidden.kind = static_cast<Kind>(0xff); // images/video/unknown attachments are not wire kinds
    CHECK_FALSE(encode(forbidden).has_value());
}

TEST_CASE("StrangeNet carries explicit session profiles without opening arbitrary media", "[strangenet][profile]") {
    const Message profile{"mainnet/friends", "peer-alice", 13, 1700000000129ULL,
        R"({"name":"Alice","intent":"friendship","bio":"Here for thoughtful conversation"})",
        Kind::Profile};
    const auto wire = encode(profile);
    REQUIRE(wire.has_value());
    const auto decoded = decode(*wire);
    REQUIRE(decoded.has_value());
    CHECK(decoded->kind == Kind::Profile);
    CHECK(decoded->text == profile.text);
}

TEST_CASE("StrangeNet carries authenticated bounded world state", "[strangenet][world]") {
    const Message world{"mainnet/friends", "peer-alice", 14, 1700000000130ULL,
        R"({"v":1,"op":"move","zone":"commons","x":420,"y":610,"facing":"east","emote":"wave"})",
        Kind::World};
    const auto wire = encode(world);
    REQUIRE(wire.has_value());
    const auto decoded = decode(*wire);
    REQUIRE(decoded.has_value());
    CHECK(decoded->kind == Kind::World);
    CHECK(decoded->text == world.text);
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

    bob.set_strangenet_peer_blocked(alice_id, true);
    CHECK(bob.is_strangenet_peer_blocked(alice_id));
    const auto blocked_frame = alice.build_strangenet_datagram(
        bob_id, "riemann-lab", 2, 43, "must not reach the handler");
    REQUIRE(blocked_frame.has_value());
    io.restart();
    asio::co_spawn(io, bob.datagram_received(*blocked_frame, alice_endpoint), asio::detached);
    io.run();
    CHECK(received.size() == 1);

    bob.set_strangenet_peer_blocked(alice_id, false);
    CHECK_FALSE(bob.is_strangenet_peer_blocked(alice_id));
    const auto restored_frame = alice.build_strangenet_datagram(
        bob_id, "riemann-lab", 3, 44, "delivery restored");
    REQUIRE(restored_frame.has_value());
    io.restart();
    asio::co_spawn(io, bob.datagram_received(*restored_frame, alice_endpoint), asio::detached);
    io.run();
    REQUIRE(received.size() == 2);
    CHECK(received.back().text == "delivery restored");
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

TEST_CASE("StrangeNet groups have no central secret or reusable group ciphertext", "[strangenet][group][crypto]") {
    asio::io_context io;
    pqvpn::PQVPNNode alice{io}, bob{io};
    const std::vector<std::uint8_t> alice_id(32, 0x41), bob_id(32, 0x42), carol_id(32, 0x43);
    const asio::ip::udp::endpoint alice_endpoint{asio::ip::make_address("127.0.0.1"), 9301};
    const asio::ip::udp::endpoint bob_endpoint{asio::ip::make_address("127.0.0.1"), 9302};
    const asio::ip::udp::endpoint carol_endpoint{asio::ip::make_address("127.0.0.1"), 9303};
    const std::vector<std::uint8_t> bob_x25519(32, 0x51), bob_ml_kem(32, 0x52);
    const std::vector<std::uint8_t> carol_x25519(32, 0x61), carol_ml_kem(32, 0x62);
    const std::vector<std::uint8_t> bob_transcript{'G','R','O','U','P','-','B'};
    const std::vector<std::uint8_t> carol_transcript{'G','R','O','U','P','-','C'};
    alice.set_my_id(alice_id);
    bob.set_my_id(bob_id);
    REQUIRE(alice.establish_hybrid_session(bob_id, bob_endpoint, bob_x25519, bob_ml_kem, bob_transcript, true));
    REQUIRE(bob.establish_hybrid_session(alice_id, alice_endpoint, bob_x25519, bob_ml_kem, bob_transcript, false));
    REQUIRE(alice.establish_hybrid_session(carol_id, carol_endpoint, carol_x25519, carol_ml_kem, carol_transcript, true));

    const auto for_bob = alice.build_strangenet_datagram(bob_id, "three-person-room", 1, 42, "one plaintext");
    const auto for_carol = alice.build_strangenet_datagram(carol_id, "three-person-room", 1, 42, "one plaintext");
    REQUIRE(for_bob.has_value());
    REQUIRE(for_carol.has_value());
    CHECK(*for_bob != *for_carol);

    std::vector<Message> received;
    bob.set_strangenet_handler([&](const Message& message, const std::vector<std::uint8_t>&) {
        received.push_back(message);
    });
    asio::co_spawn(io, bob.datagram_received(*for_carol, alice_endpoint), asio::detached);
    io.run();
    CHECK(received.empty());
    io.restart();
    asio::co_spawn(io, bob.datagram_received(*for_bob, alice_endpoint), asio::detached);
    io.run();
    REQUIRE(received.size() == 1);
    CHECK(received.front().text == "one plaintext");
}
