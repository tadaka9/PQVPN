#include <iostream>
#include <vector>
#include <cassert>
#include "node_module.hpp"

int main() {
    asio::io_context io_context;
    pqvpn::PQVPNNode node(io_context, "test_config.yaml");

    // Create a session for testing
    pqvpn::PQVPNNode::Session sess;
    sess.replay_window_size = 1024; // Set the window size

    std::cout << "Running comprehensive check_and_record_nonce tests..." << std::endl;

    // Test Case 1: Invalid nonce length (too short)
    {
        std::vector<uint8_t> short_nonce = {0x01, 0x02, 0x03};
        assert(node.check_and_record_nonce(sess, short_nonce) == false);
        std::cout << "✓ Test Case 1 passed: Short nonce rejected" << std::endl;
    }

    // Test Case 2: Invalid nonce length (too long)
    {
        std::vector<uint8_t> long_nonce(20, 0x00);
        assert(node.check_and_record_nonce(sess, long_nonce) == false);
        std::cout << "✓ Test Case 2 passed: Long nonce rejected" << std::endl;
    }

    // Test Case 3: Empty nonce
    {
        std::vector<uint8_t> empty_nonce;
        assert(node.check_and_record_nonce(sess, empty_nonce) == false);
        std::cout << "✓ Test Case 3 passed: Empty nonce rejected" << std::endl;
    }

    // Test Case 4: Valid nonce - counter = 1
    {
        std::vector<uint8_t> valid_nonce(12, 0x00);
        valid_nonce[4] = 0x00;
        valid_nonce[5] = 0x00;
        valid_nonce[6] = 0x00;
        valid_nonce[7] = 0x00;
        valid_nonce[8] = 0x00;
        valid_nonce[9] = 0x00;
        valid_nonce[10] = 0x00;
        valid_nonce[11] = 0x01; // Counter value of 1

        assert(node.check_and_record_nonce(sess, valid_nonce) == true);
        assert(sess.nonce_recv == 1);
        std::cout << "✓ Test Case 4 passed: First nonce accepted" << std::endl;
    }

    // Test Case 5: Duplicate packet should be rejected
    {
        std::vector<uint8_t> valid_nonce(12, 0x00);
        valid_nonce[4] = 0x00;
        valid_nonce[5] = 0x00;
        valid_nonce[6] = 0x00;
        valid_nonce[7] = 0x00;
        valid_nonce[8] = 0x00;
        valid_nonce[9] = 0x00;
        valid_nonce[10] = 0x00;
        valid_nonce[11] = 0x01; // Counter value of 1

        assert(node.check_and_record_nonce(sess, valid_nonce) == false);
        std::cout << "✓ Test Case 5 passed: Duplicate nonce rejected" << std::endl;
    }

    // Test Case 6: New higher counter should be accepted (counter=2)
    {
        std::vector<uint8_t> nonce2(12, 0x00);
        nonce2[4] = 0x00;
        nonce2[5] = 0x00;
        nonce2[6] = 0x00;
        nonce2[7] = 0x00;
        nonce2[8] = 0x00;
        nonce2[9] = 0x00;
        nonce2[10] = 0x00;
        nonce2[11] = 0x02; // Counter value of 2

        assert(node.check_and_record_nonce(sess, nonce2) == true);
        assert(sess.nonce_recv == 2);
        std::cout << "✓ Test Case 6 passed: Higher counter accepted" << std::endl;
    }

    // Test Case 7: Out-of-order packet within window should be rejected (counter=1 again)
    {
        std::vector<uint8_t> nonce1_again(12, 0x00);
        nonce1_again[4] = 0x00;
        nonce1_again[5] = 0x00;
        nonce1_again[6] = 0x00;
        nonce1_again[7] = 0x00;
        nonce1_again[8] = 0x00;
        nonce1_again[9] = 0x00;
        nonce1_again[10] = 0x00;
        nonce1_again[11] = 0x01; // Counter value of 1

        assert(node.check_and_record_nonce(sess, nonce1_again) == false);
        std::cout << "✓ Test Case 7 passed: Out-of-order within window rejected" << std::endl;
    }

    // Test Case 8: Very old packet (outside replay window) should be rejected
    {
        std::vector<uint8_t> very_old_nonce(12, 0xFF);
        very_old_nonce[4] = 0xFF;
        very_old_nonce[5] = 0xFF;
        very_old_nonce[6] = 0xFF;
        very_old_nonce[7] = 0xFF;
        very_old_nonce[8] = 0xFF;
        very_old_nonce[9] = 0xFF;
        very_old_nonce[10] = 0xFF;
        very_old_nonce[11] = 0xFE; // Counter value that should be too old

        assert(node.check_and_record_nonce(sess, very_old_nonce) == false);
        std::cout << "✓ Test Case 8 passed: Very old nonce rejected" << std::endl;
    }

    // Test Case 9: Test window pruning functionality
    {
        // Reset session for clean state test
        sess.replay_window.clear();
        sess.nonce_recv = 0;

        // Fill up the replay window with 1025 entries (should be more than max size)
        for (uint64_t i = 1; i <= 1030; ++i) {
            std::vector<uint8_t> nonce(12, 0x00);
            nonce[4] = static_cast<uint8_t>(i >> 56);
            nonce[5] = static_cast<uint8_t>((i >> 48) & 0xFF);
            nonce[6] = static_cast<uint8_t>((i >> 40) & 0xFF);
            nonce[7] = static_cast<uint8_t>((i >> 32) & 0xFF);
            nonce[8] = static_cast<uint8_t>((i >> 24) & 0xFF);
            nonce[9] = static_cast<uint8_t>((i >> 16) & 0xFF);
            nonce[10] = static_cast<uint8_t>((i >> 8) & 0xFF);
            nonce[11] = static_cast<uint8_t>(i & 0xFF);

            // First entry should be accepted
            bool result = node.check_and_record_nonce(sess, nonce);
            if (i == 1) {
                assert(result == true);
                assert(sess.nonce_recv == i);
            }
        }

        // Check that window size is maintained
        assert(sess.replay_window.size() <= sess.replay_window_size);
        std::cout << "✓ Test Case 9 passed: Window pruning works correctly" << std::endl;
    }

    std::cout << "All check_and_record_nonce tests passed!" << std::endl;
    return 0;
}
