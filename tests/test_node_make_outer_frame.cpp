#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <cstdint>
#include "../src/modules/node_module.hpp"

TEST_CASE("PQVPNNode::make_outer_frame correctly constructs the frame", "[node][serialization]") {
    pqvpn::PQVPNNode node("config.yaml");

    uint8_t frame_type = 0x05; // FT_RELAY equivalent
    std::vector<uint8_t> next_hop_hash = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
    uint32_t circuit_id = 12345;
    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};

    std::vector<uint8_t> frame = node.make_outer_frame(frame_type, next_hop_hash, circuit_id, payload);

    // Total size: 1 (ver) + 1 (type) + 8 (hash) + 4 (cid) + 2 (len) + 4 (payload) = 20
    REQUIRE(frame.size() == 20);

    // Version
    CHECK(frame[0] == 1);
    // Type
    CHECK(frame[1] == 0x05);
    // Next Hop Hash
    std::vector<uint8_t> extracted_hash(frame.begin() + 2, frame.begin() + 10);
    CHECK(extracted_hash == next_hop_hash);
    // Circuit ID (Big Endian)
    uint32_t extracted_cid = (static_cast<uint32_t>(frame[10]) << 24) |
                             (static_cast<uint32_t>(frame[11]) << 16) |
                             (static_cast<uint32_t>(frame[12]) << 8)  |
                              static_cast<uint32_t>(frame[13]);
    CHECK(extracted_cid == circuit_id);
    // Length (Big Endian)
    uint16_t extracted_len = (static_cast<uint16_t>(frame[14]) << 8) |
                              static_cast<uint16_t>(frame[15]);
    CHECK(extracted_len == 4);
    // Payload
    std::vector<uint8_t> extracted_payload(frame.begin() + 16, frame.end());
    CHECK(extracted_payload == payload);
}
