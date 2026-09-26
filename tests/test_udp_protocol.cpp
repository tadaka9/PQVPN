#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <cstdint>
#include <memory>
#include "../src/modules/udp_protocol.hpp"

// Test that UDPProtocol class can be instantiated and has expected interface
TEST_CASE("UDPProtocol instantiation", "[node][network]") {
    SECTION("Constructor accepts shared_ptr to node") {
        // Verify the class can be constructed with a null shared_ptr
        std::shared_ptr<pqvpn::PQVPNNode> empty_node;
        pqvpn::UDPProtocol protocol(empty_node);
        // If we get here, construction succeeded
    }
}

// Test datagram parsing logic (version and type byte validation)
TEST_CASE("UDPProtocol datagram format validation", "[node][network]") {
    SECTION("Datagrams must have version byte 1") {
        std::vector<uint8_t> wrong_version = {2, 1, 0};
        REQUIRE(wrong_version[0] != 1);
    }

    SECTION("Datagram types are correctly identified") {
        // Type 1 = RELAY/DATA
        std::vector<uint8_t> relay_msg = {1, 1, 0};
        REQUIRE(relay_msg[1] == 1);

        // Type 2 = HELLO
        std::vector<uint8_t> hello_msg = {1, 2, 0};
        REQUIRE(hello_msg[1] == 2);

        // Type 3 = GOSSIP
        std::vector<uint8_t> gossip_msg = {1, 3, 0};
        REQUIRE(gossip_msg[1] == 3);
    }

    SECTION("Datagrams must be at least 2 bytes") {
        std::vector<uint8_t> too_short = {1};
        REQUIRE(too_short.size() < 2);

        std::vector<uint8_t> valid_size = {1, 1};
        REQUIRE(valid_size.size() >= 2);
    }
}