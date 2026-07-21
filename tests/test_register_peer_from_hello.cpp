#include <gtest/gtest.h>
#include "src/modules/node_module.hpp"
#include <asio.hpp>

// Test for register_peer_from_hello method in PQVPNNode
TEST(PQVPNNodeTest, RegisterPeerFromHello) {
    // Create a test node instance
    pqvpn::PQVPNNode node("test_config.yaml");

    // Set up a mock endpoint address
    asio::ip::udp::endpoint addr(asio::ip::address::from_string("127.0.0.1"), 9000);

    // Test case 1: Valid peer with all fields
    std::map<std::string, std::string> valid_hello = {
        {"peerid", "a1b2c3d4e5f6"},
        {"ed25519_pk", "11223344556677889900aabbccddeeff"},
        {"brainpoolP512r1_pk", "ffeeddccbbaa99887766554433221100"},
        {"kyber_pk", "00112233445566778899aabbccddeeff"},
        {"mldsa_pk", "f0e0d0c0b0a090807060504030201000"},
        {"nickname", "test_peer_1"},
        {"relay", "true"}
    };

    auto result = node.register_peer_from_hello(valid_hello, addr);
    ASSERT_TRUE(result.has_value());

    // Check that the peer info was created correctly
    const auto& pinfo = result.value();
    EXPECT_EQ(pinfo.peer_id.size(), 6);  // a1b2c3d4e5f6 -> 6 bytes

    // Check nickname
    EXPECT_EQ(pinfo.nickname, "test_peer_1");

    // Check relay flag
    EXPECT_TRUE(pinfo.is_relay);

    // Check public keys were parsed correctly
    EXPECT_EQ(pinfo.ed25519_pk.size(), 16);
    EXPECT_EQ(pinfo.brainpoolP512r1_pk.size(), 16);
    EXPECT_EQ(pinfo.kyber_pk.size(), 16);
    EXPECT_EQ(pinfo.mldsa_pk.size(), 16);

    // Test case 2: Peer with minimal information
    std::map<std::string, std::string> minimal_hello = {
        {"peerid", "abcdef123456"},
        {"nickname", "minimal_peer"}
    };

    auto result2 = node.register_peer_from_hello(minimal_hello, addr);
    ASSERT_TRUE(result2.has_value());

    const auto& pinfo2 = result2.value();
    EXPECT_EQ(pinfo2.peer_id.size(), 6);  // abcdef123456 -> 6 bytes
    EXPECT_EQ(pinfo2.nickname, "minimal_peer");
    EXPECT_FALSE(pinfo2.is_relay);

    // Test case 3: Invalid peer ID (not hex)
    std::map<std::string, std::string> invalid_hello = {
        {"peerid", "invalid_hex_value"},
        {"nickname", "bad_peer"}
    };

    auto result3 = node.register_peer_from_hello(invalid_hello, addr);
    EXPECT_FALSE(result3.has_value());

    // Test case 4: Empty peer ID
    std::map<std::string, std::string> empty_hello = {
        {"peerid", ""},
        {"nickname", "empty_id"}
    };

    auto result4 = node.register_peer_from_hello(empty_hello, addr);
    EXPECT_FALSE(result4.has_value());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}