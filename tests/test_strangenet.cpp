#include <catch2/catch_test_macros.hpp>
#include "strangenet.hpp"

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
