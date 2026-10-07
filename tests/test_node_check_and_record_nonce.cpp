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
        assert(node.check_and_record_nonce(sess, sess.data_domain, short_nonce) == false);
        std::cout << "✓ Test Case 1 passed: Short nonce rejected" << std::endl;
    }

    // Test Case 2: Invalid nonce length (too long)
    {
        std::vector<uint8_t> long_nonce(20, 0x00);
        assert(node.check_and_record_nonce(sess, sess.data_domain, long_nonce) == false);
        std::cout << "✓ Test Case 2 passed: Long nonce rejected" << std::endl;
    }

    // Test Case 3: Empty nonce
    {
        std::vector<uint8_t> empty_nonce;
        assert(node.check_and_record_nonce(sess, sess.data_domain, empty_nonce) == false);
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

        assert(node.check_and_record_nonce(sess, sess.data_domain, valid_nonce) == true);
        assert(sess.data_domain.high_water == 1);
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

        assert(node.check_and_record_nonce(sess, sess.data_domain, valid_nonce) == false);
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

        assert(node.check_and_record_nonce(sess, sess.data_domain, nonce2) == true);
        assert(sess.data_domain.high_water == 2);
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

        assert(node.check_and_record_nonce(sess, sess.data_domain, nonce1_again) == false);
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

        assert(node.check_and_record_nonce(sess, sess.data_domain, very_old_nonce) == false);
        std::cout << "✓ Test Case 8 passed: Very old nonce rejected" << std::endl;
    }

    // Test Case 9: Test window pruning functionality
    {
        // Reset session for clean state test
        sess.data_domain.window.clear();
        sess.data_domain.high_water = 0;

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
            bool result = node.check_and_record_nonce(sess, sess.data_domain, nonce);
            if (i == 1) {
                assert(result == true);
                assert(sess.data_domain.high_water == i);
            }
        }

        // Check that window size is maintained
        assert(sess.data_domain.window.size() <= sess.replay_window_size);
        std::cout << "✓ Test Case 9 passed: Window pruning works correctly" << std::endl;
    }

    // Test Case 10: domains are independent. An onion layer accepted into
    // relay_domain (counter 5) must not evict a lower fresh tunnel-data counter
    // (4) from data_domain — the exact ordering an onion delivery produces when
    // both frames ride on one source-destination session.
    {
        // Clean slate: test case 9 left counters recorded in data_domain.
        sess.data_domain.window.clear();
        sess.data_domain.high_water = 0;
        sess.relay_domain.window.clear();
        sess.relay_domain.high_water = 0;

        auto make_nonce = [](uint64_t counter) {
            std::vector<uint8_t> nonce(12, 0x00);
            for (int shift = 56; shift >= 0; shift -= 8) {
                nonce[4 + (56 - shift) / 8] = static_cast<uint8_t>((counter >> shift) & 0xFF);
            }
            return nonce;
        };

        // Relay layer counter 5 lands in relay_domain first...
        assert(node.check_and_record_nonce(sess, sess.relay_domain, make_nonce(5)) == true);
        // ...then the inner tunnel-data frame's lower counter is still fresh in
        // data_domain.
        assert(node.check_and_record_nonce(sess, sess.data_domain, make_nonce(4)) == true);
        // The reverse interleaving holds too: a higher data-domain counter does
        // not block a lower relay-domain one...
        assert(node.check_and_record_nonce(sess, sess.data_domain, make_nonce(9)) == true);
        assert(node.check_and_record_nonce(sess, sess.relay_domain, make_nonce(7)) == true);
        // ...and strict monotonicity still holds WITHIN each domain.
        assert(node.check_and_record_nonce(sess, sess.data_domain, make_nonce(4)) == false);
        assert(node.check_and_record_nonce(sess, sess.relay_domain, make_nonce(5)) == false);
        std::cout << "✓ Test Case 10 passed: nonce domains are independent" << std::endl;
    }

    // Test Case 11: counter zero is rejected even on a fresh domain. The C++
    // wire contract starts every session's send counter at 1 (pre-increment),
    // and the peeler rejects any counter at or below the high-water mark,
    // whose initial value is 0 — so there is no "first nonce" special case to
    // tolerate. This deliberately diverges from main.py, where the builder
    // emits counter 0 first and the peeler accepts it through its out-of-order
    // tolerance branch (see MIGRATION_MANIFEST.md, documented deviations).
    {
        sess.data_domain.window.clear();
        sess.data_domain.high_water = 0;

        std::vector<uint8_t> zero_nonce(12, 0x00); // counter = 0
        assert(node.check_and_record_nonce(sess, sess.data_domain, zero_nonce) == false);
        assert(sess.data_domain.high_water == 0);
        assert(sess.data_domain.window.empty());

        // And the first accepted nonce of a fresh domain is exactly counter 1.
        std::vector<uint8_t> first_nonce(12, 0x00);
        first_nonce[11] = 0x01;
        assert(node.check_and_record_nonce(sess, sess.data_domain, first_nonce) == true);
        assert(sess.data_domain.high_water == 1);
        std::cout << "✓ Test Case 11 passed: counter zero rejected; fresh domains start at one" << std::endl;
    }

    std::cout << "All check_and_record_nonce tests passed!" << std::endl;
    return 0;
}
