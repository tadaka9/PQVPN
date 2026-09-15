#include <iostream>
#include <vector>
#include <cassert>
#include <cstring>
#include "src/modules/node_module.hpp"
#include "src/modules/crypto_module.hpp"

// Mock a session to test the build_onion_frame function
void test_build_onion_frame() {
    try {
        pqvpn::PQVPNNode node("test_config.toml");
        // The builder binds the source identity into the outer layer's AAD;
        // production nodes always have one (establish_identity at startup).
        node.set_my_id(std::vector<uint8_t>(32, 0x5A));

        // Create mock data for testing
        std::vector<uint8_t> inner_frame = {0xDE, 0xAD, 0xBE, 0xEF};

    // Create a path with two peers for a simple onion route.
        std::vector<std::vector<uint8_t>> path = {
            {0x11, 0x22, 0x33, 0x44},  // First hop (destination)
            {0xAA, 0xBB, 0xCC, 0xDD}   // Second hop (source)
        };

        // The builder (main.py parity) needs a session for every hop that will
        // peel a layer: here path[0] peels the single encrypted layer.
        auto first_session = std::make_shared<pqvpn::PQVPNNode::Session>();
        first_session->session_id = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
        first_session->session_iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0A, 0x0B}; // 12-byte IV
        first_session->aead_send_key = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                                        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}; // 16-byte key
        first_session->state = pqvpn::PQVPNNode::SessionState::ESTABLISHED;

        auto second_session = std::make_shared<pqvpn::PQVPNNode::Session>();
        second_session->session_id = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x78, 0x90};
        second_session->session_iv = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                      0x18, 0x19, 0x1A, 0x1B}; // 12-byte IV
        second_session->aead_send_key = {0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88,
                                         0x7F, 0x6E, 0x5D, 0x4C, 0x3B, 0x2A, 0x19, 0x08}; // 16-byte key
        second_session->state = pqvpn::PQVPNNode::SessionState::ESTABLISHED;

        node.sessions_by_peer_id[path[0]] = first_session;   // peels the layer (main.py: hop = path[i-1])
        node.sessions_by_peer_id[path[1]] = second_session;

        // Build onion frame
        auto result = node.build_onion_frame(path, inner_frame);

        assert(result.has_value());
        std::cout << "build_onion_frame test PASSED" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test FAILED: " << e.what() << std::endl;
        throw;
    }
}

int main() {
    try {
        test_build_onion_frame();
        std::cout << "All tests PASSED" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test suite FAILED: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
