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

        // Create mock data for testing
        std::vector<uint8_t> inner_frame = {0xDE, 0xAD, 0xBE, 0xEF};

    // Create a path with two peers for a simple onion route.
        std::vector<std::vector<uint8_t>> path = {
            {0x11, 0x22, 0x33, 0x44},  // First hop (destination)
            {0xAA, 0xBB, 0xCC, 0xDD}   // Second hop (source)
        };

        // Create mock session for the second hop
        auto session = std::make_shared<pqvpn::PQVPNNode::Session>();
        session->session_id = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
        session->session_iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0A, 0x0B}; // 12-byte IV
        session->aead_send_key = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                                  0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}; // 16-byte key

        node.sessions_by_peer_id[path[1]] = session;

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
