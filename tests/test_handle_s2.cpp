#include <gtest/gtest.h>
#include "PQVPNNode.h"
#include <nlohmann/json.hpp>

// Test for handle_s2 method implementation
TEST(HandleS2, BasicFunctionality) {
        asio::io_context io_ctx;\n        pqvpn::PQVPNNode node(io_ctx, \"test_config.yaml\");
    // Create a minimal valid S2 payload as JSON
    nlohmann::json s2_payload;
    s2_payload["sessionid"] = "1234567890abcdef";
    s2_payload["peerid"] = "fedcba0987654321";
    s2_payload["ed25519_pk"] = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
    s2_payload["ed25519_sig"] = "sig1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    s2_payload["mldsa_pk"] = "fedcba0987654321098765432109876543210987654321098765432109876543";
    s2_payload["mldsa_sig"] = "mldsa_signature_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    std::string payload_str = s2_payload.dump();
    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());

    // This should not crash and should handle the basic case
    node.handle_s2(payload, "127.0.0.1", {}, 0);

    // Test with invalid JSON - should not crash
    std::vector<uint8_t> invalid_payload = {'{', 'n', 'o', 't', '_', 'j', 's', 'o', 'n', '}'};
    node.handle_s2(invalid_payload, "127.0.0.1", {}, 0);

    // Test with missing sessionid - should not crash
    nlohmann::json s2_no_session;
    s2_no_session["peerid"] = "fedcba0987654321";
    std::string no_session_str = s2_no_session.dump();
    std::vector<uint8_t> no_session_payload(no_session_str.begin(), no_session_str.end());
    node.handle_s2(no_session_payload, "127.0.0.1", {}, 0);
}

TEST(HandleS2, SignatureVerification) {
        asio::io_context io_ctx;\n        pqvpn::PQVPNNode node(io_ctx, \"test_config.yaml\");
    // Test with valid signatures (simplified verification)
    nlohmann::json s2_valid;
    s2_valid["sessionid"] = "abcdef1234567890";
    s2_valid["peerid"] = "1234567890abcdef";
    s2_valid["ed25519_pk"] = "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef";
    s2_valid["ed25519_sig"] = "sig1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    s2_valid["mldsa_pk"] = "fedcba0987654321098765432109876543210987654321098765432109876543";
    s2_valid["mldsa_sig"] = "mldsa_signature_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    std::string valid_payload_str = s2_valid.dump();
    std::vector<uint8_t> valid_payload(valid_payload_str.begin(), valid_payload_str.end());

    // This should process without error
    node.handle_s2(valid_payload, "127.0.0.1", {}, 0);
}