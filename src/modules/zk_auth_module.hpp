#ifndef ZK_AUTH_MODULE_HPP
#define ZK_AUTH_MODULE_HPP

#include <map>
#include <set>
#include <vector>
#include <cstdint>
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdexcept>
#include "logging_module.hpp"

class ZeroKnowledgeAuthTestFriend;

namespace pqvpn {

class ZeroKnowledgeAuth {
public:
    struct InternalState {
        std::map<std::vector<uint8_t>, std::vector<uint8_t>> zk_challenges;
        std::map<std::vector<uint8_t>, std::vector<uint8_t>> credential_store;
        std::set<std::vector<uint8_t>> revocation_list;
    };

    ZeroKnowledgeAuth() {
        zk_challenges = {};
        credential_store = {};
        revocation_list = {};
    }

    void set_internal_state(InternalState state) {
        zk_challenges = std::move(state.zk_challenges);
        credential_store = std::move(state.credential_store);
        revocation_list = std::move(state.revocation_list);
    }

    std::vector<uint8_t> issue_challenge(const std::vector<uint8_t>& peer_id) {
        std::vector<uint8_t> challenge(32);
        if (RAND_bytes(challenge.data(), 32) != 1) {
            throw std::runtime_error("Failed to generate random challenge");
        }
        zk_challenges[peer_id] = challenge;

        std::stringstream ss;
        for (size_t i = 0; i < std::min<size_t>(peer_id.size(), 4); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(peer_id[i]);
        }
        logging::Logger::debug("ZK challenge issued to " + ss.str());

        return challenge;
    }

    std::vector<uint8_t> issue_credential(const std::vector<uint8_t>& peer_id) {
        // Python: credential = hashlib.sha256(peer_id + os.urandom(32)).digest()
        std::vector<uint8_t> salt(32);
        if (RAND_bytes(salt.data(), 32) != 1) {
            throw std::runtime_error("Failed to generate random salt");
        }

        std::vector<uint8_t> data = peer_id;
        data.insert(data.end(), salt.begin(), salt.end());

        std::vector<uint8_t> credential(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), credential.data());

        credential_store[peer_id] = credential;
        return credential;
    }

    bool verify_response(const std::vector<uint8_t>& peer_id,
                         const std::vector<uint8_t>& challenge,
                         const std::vector<uint8_t>& response,
                         const std::vector<uint8_t>& peer_pk) {
        auto it = zk_challenges.find(peer_id);
        if (it == zk_challenges.end() || it->second != challenge) {
            return false;
        }

        // Python: expected_response = hashlib.sha256(challenge + peer_pk).digest()
        std::vector<uint8_t> data = challenge;
        data.insert(data.end(), peer_pk.begin(), peer_pk.end());

        std::vector<uint8_t> expected_response(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), expected_response.data());

        bool is_valid = true;
        if (response.size() < 16) {
            is_valid = false;
        } else {
            for (size_t i = 0; i < 16; ++i) {
                if (response[i] != expected_response[i]) {
                    is_valid = false;
                    break;
                }
            }
        }

        std::stringstream ss;
        for (size_t i = 0; i < std::min<size_t>(peer_id.size(), 4); ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(peer_id[i]);
        }

        if (is_valid) {
            logging::Logger::info("ZK auth verified for " + ss.str());
        } else {
            logging::Logger::warn("ZK auth failed for " + ss.str());
        }

        return is_valid;
    }

private:
    friend class ::ZeroKnowledgeAuthTestFriend;
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> zk_challenges;
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> credential_store;
    std::set<std::vector<uint8_t>> revocation_list;
};

} // namespace pqvpn

#endif // ZK_AUTH_MODULE_HPP
