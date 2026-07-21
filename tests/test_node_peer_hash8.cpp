#include <catch2/catch_test_macros.hpp>
#include "node_module.hpp"
#include <vector>
#include <cstdint>

TEST_CASE("PQVPNNode::peer_hash8 provides deterministic 8-byte hash", "[pqvpn][node]") {
    pqvpn::PQVPNNode node("config.json");

    SECTION("Empty peer ID") {
        std::vector<uint8_t> peer_id = {};
        auto hash = node.peer_hash8(peer_id);
        REQUIRE(hash.size() == 8);
        // hashlib.sha256(b"").digest()[:8]
        std::vector<uint8_t> expected = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14};
        REQUIRE(hash == expected);
    }

    SECTION("Known peer ID") {
        std::vector<uint8_t> peer_id = {0x01, 0x02, 0x03, 0x04};
        auto hash = node.peer_hash8(peer_id);
        // hashlib.sha256(bytes([1,2,3,4])).digest()[:8]
        std::vector<uint8_t> expected = {0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13};
        REQUIRE(hash == expected);
    }
}
