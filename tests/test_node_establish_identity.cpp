#include <gtest/gtest.h>

#include <asio.hpp>
#include <cstdint>
#include <string>
#include <vector>

#include "node_module.hpp"

namespace {

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

} // namespace

TEST(NodeIdentity, EstablishesFromEd25519KeyPerReference) {
    asio::io_context io;
    pqvpn::PQVPNNode node{io};
    const std::vector<uint8_t> ed25519_pk(32, 0x41); // representative 32-byte public key
    node.ed25519_public_key = ed25519_pk;

    EXPECT_TRUE(node.establish_identity());
    ASSERT_TRUE(node.my_id_.has_value());
    // my_id is SHA256 of the ed25519 public key (a 32-byte digest).
    const auto expected = hex_to_bytes(
        "22a48051594c1949deed7040850c1f0f8764537f5191be56732d16a54c1d8153");
    EXPECT_EQ(*node.my_id_, expected);
}

TEST(NodeIdentity, FailsClosedWithoutAnEd25519Key) {
    asio::io_context io;
    pqvpn::PQVPNNode node{io};

    EXPECT_FALSE(node.establish_identity());
    EXPECT_FALSE(node.my_id_.has_value());
}

TEST(NodeIdentity, KeepsAnExplicitlySetIdentity) {
    asio::io_context io;
    pqvpn::PQVPNNode node{io};
    const std::vector<uint8_t> explicit_id(32, 0x11);
    node.set_my_id(explicit_id);
    node.ed25519_public_key.assign(32, 0x41);

    EXPECT_TRUE(node.establish_identity());
    // The explicitly set identity must not be overwritten by derivation.
    EXPECT_EQ(*node.my_id_, explicit_id);
}
