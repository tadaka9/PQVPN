#include "src/modules/zk_auth_module.hpp"
#include <catch2/catch_test_macros.hpp>
#include <vector>

class ZeroKnowledgeAuthTestFriend {
public:
    static const auto& get_zk_challenges(const pqvpn::ZeroKnowledgeAuth& auth) { return auth.zk_challenges; }
    static const auto& get_credential_store(const pqvpn::ZeroKnowledgeAuth& auth) { return auth.credential_store; }
    static const auto& get_revocation_list(const pqvpn::ZeroKnowledgeAuth& auth)  { return auth.revocation_list; }
};

TEST_CASE("ZeroKnowledgeAuth initialization", "[zk_auth]") {
    pqvpn::ZeroKnowledgeAuth zk_auth;

    CHECK(ZeroKnowledgeAuthTestFriend::get_zk_challenges(zk_auth).empty());
    CHECK(ZeroKnowledgeAuthTestFriend::get_credential_store(zk_auth).empty());
    CHECK(ZeroKnowledgeAuthTestFriend::get_revocation_list(zk_auth).empty());
}

TEST_CASE("ZeroKnowledgeAuth issue_challenge", "[zk_auth]") {
    pqvpn::ZeroKnowledgeAuth zk_auth;
    std::vector<uint8_t> peer_id = {0xDE, 0xAD, 0xBE, 0xEF};

    auto challenge = zk_auth.issue_challenge(peer_id);

    CHECK(challenge.size() == 32);

    const auto& challenges = ZeroKnowledgeAuthTestFriend::get_zk_challenges(zk_auth);
    REQUIRE(challenges.count(peer_id) == 1);
    CHECK(challenges.at(peer_id) == challenge);
}

TEST_CASE("ZeroKnowledgeAuth issue_credential", "[zk_auth]") {
    pqvpn::ZeroKnowledgeAuth zk_auth;
    std::vector<uint8_t> peer_id = {0xDE, 0xAD, 0xBE, 0xEF};

    auto credential = zk_auth.issue_credential(peer_id);

    CHECK(credential.size() == 32);
    CHECK(credential != std::vector<uint8_t>(32, 0));

    const auto& creds = ZeroKnowledgeAuthTestFriend::get_credential_store(zk_auth);
    REQUIRE(creds.count(peer_id) == 1);
    CHECK(creds.at(peer_id) == credential);
}

TEST_CASE("ZeroKnowledgeAuth verify_response", "[zk_auth]") {
    pqvpn::ZeroKnowledgeAuth zk_auth;
    std::vector<uint8_t> peer_id = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> challenge = zk_auth.issue_challenge(peer_id);
    std::vector<uint8_t> peer_pk = {0x11, 0x22, 0x33, 0x44};

    // Test failure: wrong challenge
    std::vector<uint8_t> bad_challenge = std::vector<uint8_t>(32, 0xFF);
    std::vector<uint8_t> response(16, 0xBB);
    CHECK(zk_auth.verify_response(peer_id, bad_challenge, response, peer_pk) == false);

    // Test success: Python parity uses SHA256(challenge + peer public key), first 16 bytes.
    std::vector<uint8_t> response_input = challenge;
    response_input.insert(response_input.end(), peer_pk.begin(), peer_pk.end());
    std::vector<uint8_t> full_response(SHA256_DIGEST_LENGTH);
    SHA256(response_input.data(), response_input.size(), full_response.data());
    std::vector<uint8_t> good_response(full_response.begin(), full_response.begin() + 16);
    CHECK(zk_auth.verify_response(peer_id, challenge, good_response, peer_pk) == true);

    // Test failure: response too short
    std::vector<uint8_t> short_response = {0xBB};
    CHECK(zk_auth.verify_response(peer_id, challenge, short_response, peer_pk) == false);
}
