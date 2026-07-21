#include <gtest/gtest.h>
#include "PQVPNNode.h"
#include <vector>
#include <string>

// Test for the handle_hello method implementation
TEST(PQVPNNodeTest, HandleHelloEmptyPayload)
{
    PQVPNNode node;

    // Test with empty payload - should not crash or do anything
    std::vector<uint8_t> empty_payload;
    node.handle_hello(empty_payload, "127.0.0.1", 8080);

    // Should complete without exception
    EXPECT_TRUE(true);
}

TEST(PQVPNNodeTest, HandleHelloInvalidJson)
{
    PQVPNNode node;

    // Test with invalid JSON payload - should not crash or do anything
    std::vector<uint8_t> invalid_json_payload = {'{', 'n', 'o', 't', '_', 'j', 's', 'o', 'n', '}'};
    node.handle_hello(invalid_json_payload, "127.0.0.1", 8080);

    // Should complete without exception
    EXPECT_TRUE(true);
}

TEST(PQVPNNodeTest, HandleHelloValidJsonNoSignatures)
{
    PQVPNNode node;

    // Test with valid JSON but no signatures - should not crash or do anything significant
    std::string valid_json = R"({
        "peerid": "1234567890abcdef",
        "nickname": "test_peer",
        "ed25519_pk": "",
        "brainpoolP512r1_pk": "",
        "kyber_pk": "",
        "mldsa_pk": "",
        "timestamp": 1234567890
    })";

    std::vector<uint8_t> payload(valid_json.begin(), valid_json.end());
    node.handle_hello(payload, "127.0.0.1", 8080);

    // Should complete without exception
    EXPECT_TRUE(true);
}

// Test that the method compiles and can be called (basic functionality)
TEST(PQVPNNodeTest, HandleHelloMethodExists)
{
    PQVPNNode node;

    // Just verify we can call the method - this is a compilation test
    std::vector<uint8_t> payload = {'{', '"', 't', 'e', 's', 't', '"', '}'};
    node.handle_hello(payload, "127.0.0.1", 8080);

    EXPECT_TRUE(true);
}