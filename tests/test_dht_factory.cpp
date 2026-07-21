#include <catch2/catch_test_macros.hpp>
#include "dht_module.hpp"
#include <stdexcept>

namespace {
class TestServer final : public pqvpn::dht::InMemoryKademliaServer {};
}

TEST_CASE("create_kademlia_server mirrors Python factory fallback", "[dht][parity]") {
    using namespace pqvpn::dht;

    SECTION("configured callable is preferred") {
        bool late_called = false;
        auto server = create_kademlia_server(
            [] { return std::make_unique<TestServer>(); },
            [&] { late_called = true; return std::make_unique<TestServer>(); });
        REQUIRE(server != nullptr);
        REQUIRE_FALSE(late_called);
    }

    SECTION("missing configured callable uses late import") {
        auto server = create_kademlia_server({}, [] { return std::make_unique<TestServer>(); });
        REQUIRE(server != nullptr);
    }

    SECTION("both unavailable returns null") {
        REQUIRE(create_kademlia_server() == nullptr);
    }

    SECTION("configured construction failure does not invoke fallback") {
        bool late_called = false;
        auto server = create_kademlia_server(
            []() -> std::unique_ptr<IKademliaServer> { throw std::runtime_error("failure"); },
            [&] { late_called = true; return std::make_unique<TestServer>(); });
        REQUIRE(server == nullptr);
        REQUIRE_FALSE(late_called);
    }

    SECTION("late import construction failure returns null") {
        auto server = create_kademlia_server(
            {}, []() -> std::unique_ptr<IKademliaServer> { throw std::runtime_error("failure"); });
        REQUIRE(server == nullptr);
    }
}
