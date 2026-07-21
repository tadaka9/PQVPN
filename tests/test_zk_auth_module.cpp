#include <catch2/catch_test_macros.hpp>
#include "zk_auth_module.hpp"
#include <vector>
#include <cstdint>

class ZeroKnowledgeAuthTest {
protected:
    pqvpn::ZeroKnowledgeAuth auth;
};

TEST_CASE("ZeroKnowledgeAuth - IssueChallengeStoresAndVerifies", "[zk_auth]") {
    pqvpn::ZeroKnowledgeAuth auth;
    std::vector<uint8_t> peer_id = {0xDE, 0xAD, 0xBE, 0xEF};
    auto challenge = auth.issue_challenge(peer_id);

    REQUIRE(challenge.size() == 32);

    // To test verification, we need a valid response.
    // Since we cannot easily compute SHA256 in the test without OpenSSL link,
    // and the implementation uses it, we will use the same logic.
    std::vector<uint8_t> peer_pk = {0x01, 0x02, 0x03};
    std::vector<uint8_t> data = challenge;
    data.insert(data.end(), peer_pk.begin(), peer_pk.end());
    std::vector<uint8_t> expected_hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), expected_hash.data());

    // The implementation checks the first 16 bytes.
    std::vector<uint8_t> response(expected_hash.begin(), expected_hash.begin() + 16);

    bool is_valid = auth.verify_response(peer_id, challenge, response, peer_pk);
    REQUIRE(is_valid == true);
}

TEST_CASE("ZeroKnowledgeAuth - VerifyResponseFailsOnWrongChallenge", "[zk_auth]") {
    pqvpn::ZeroKnowledgeAuth auth;
    std::vector<uint8_t> peer_id = {0xDE, 0xAD, 0xBE, 0xEF};
    auto challenge1 = auth.issue_challenge(peer_id);
    auto challenge2 = std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03};

    std::vector<uint8_t> response(16, 0xBB);
    std::vector<uint8_t> peer_pk = {0x01, 0x02, 0x03};

    bool is_valid_wrong = auth.verify_response(peer_id, challenge2, response, peer_pk);
    REQUIRE(is_valid_wrong == false);
}

TEST_CASE("ZeroKnowledgeAuth - IssueCredentialReturnsFixedSize", "[zk_auth]") {
    pqvpn::ZeroKnowledgeAuth auth;
    std::vector<uint8_t> peer_id = {0xDE, 0xAD, 0xBE, 0xEF};
    auto credential = auth.issue_credential(peer_id);
    REQUIRE(credential.size() == 32);
}
