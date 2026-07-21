#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <cstdint>
#include <cstring>
#include "../src/modules/node_module.hpp"
#include "../src/modules/crypto_module.hpp"

TEST_CASE("PQVPNNode::build_onion_frame_with_circuit correctly constructs the frame", "[node][onion]") {
    pqvpn::PQVPNNode node("test_config.toml");

    // Create mock data for testing
    std::vector<uint8_t> inner_frame = {0xDE, 0xAD, 0xBE, 0xEF};
    uint32_t circuit_id = 12345;

    // Create a path with two peers for a simple onion route.
    std::vector<std::vector<uint8_t>> path = {
        {0x11, 0x22, 0x33, 0x44},  // First hop (destination)
        {0xAA, 0xBB, 0xCC, 0xDD}   // Second hop (source)
    };

    // Create mock session for both hops to make sure they're available
    auto first_session = std::make_shared<pqvpn::PQVPNNode::Session>();
    first_session->session_id = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    first_session->session_iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0A, 0x0B}; // 12-byte IV
    first_session->aead_send_key = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                                    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}; // 16-byte key

    auto second_session = std::make_shared<pqvpn::PQVPNNode::Session>();
    second_session->session_id = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x78, 0x90};
    second_session->session_iv = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                  0x18, 0x19, 0x1A, 0x1B}; // 12-byte IV
    second_session->aead_send_key = {0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88,
                                     0x7F, 0x6E, 0x5D, 0x4C, 0x3B, 0x2A, 0x19, 0x08}; // 16-byte key

    node.sessions_by_peer_id[path[0]] = first_session;   // Set session for first hop (destination)
    node.sessions_by_peer_id[path[1]] = second_session;  // Set session for second hop (source)

    // Build onion frame with circuit ID
    auto result = node.build_onion_frame_with_circuit(path, inner_frame, circuit_id);

    REQUIRE(result.has_value());
    REQUIRE(result->size() > 0);

    // Verify the outer header contains our circuit id
    // Frame structure: version(1) + type(1) + next_hop_hash(8) + circuit_id(4) + length(2) + payload
    const std::vector<uint8_t>& frame = *result;

    // Check circuit ID in the header (bytes 10-13)
    uint32_t extracted_cid = (static_cast<uint32_t>(frame[10]) << 24) |
                            (static_cast<uint32_t>(frame[11]) << 16) |
                            (static_cast<uint32_t>(frame[12]) << 8) |
                             static_cast<uint32_t>(frame[13]);
    CHECK(extracted_cid == circuit_id);
}
