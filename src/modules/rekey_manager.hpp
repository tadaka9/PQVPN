#ifndef PQVPN_REKEY_MANAGER_HPP
#define PQVPN_REKEY_MANAGER_HPP

#include <unordered_map>
#include <chrono>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <memory>

namespace pqvpn {

/**
 * @brief Simple rekey manager that mimics Python's rekey logic.
 */
class RekeyManager {
public:
    /**
     * @brief Tracks last rekey time per session
     */
    struct VectorHasher {
        std::size_t operator()(const std::vector<uint8_t>& v) const {
            std::size_t seed = 0;
            for(auto x : v) {
                seed ^= std::hash<uint8_t>{}(x)
                     + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            }
            return seed;
        }
    };

    std::unordered_map<std::vector<uint8_t>, double, VectorHasher> last_rekey;

    /**
     * @brief Checks if a session should be rekeyed based on bytes sent and time elapsed.
     *
     * Ported from main.py: rekey_manager.should_rekey (main.py:4720-4731)
     */
    bool should_rekey(const std::vector<uint8_t>& sid, uint64_t bytes_sent, double last_rekey_time) {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        // Default thresholds from Python code
        constexpr uint64_t REKEY_BYTES_THRESHOLD = 1024 * 1024;  // 1MB
        constexpr double REKEY_TIME_THRESHOLD = 3600.0;         // 1 hour

        const bool traffic_limit_reached = bytes_sent > REKEY_BYTES_THRESHOLD;
        const bool time_limit_reached = (now - last_rekey_time) > REKEY_TIME_THRESHOLD;
        return traffic_limit_reached || time_limit_reached;
    }

    /**
     * @brief Performs a rekey operation for the given session.
     *
     * Returns a fresh session ID and direction-separated keys.
     */
    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>> perform_rekey(
        const std::vector<uint8_t>& sid
    ) {
        if (sid.empty()) throw std::invalid_argument("session ID cannot be empty");
        std::vector<uint8_t> entropy(32);
        std::vector<uint8_t> new_sid(sid.size());
        if (RAND_bytes(entropy.data(), static_cast<int>(entropy.size())) != 1 ||
            RAND_bytes(new_sid.data(), static_cast<int>(new_sid.size())) != 1) {
            throw std::runtime_error("secure random generation failed during rekey");
        }
        const auto derive = [&](const std::string_view label) {
            std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
                EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
            std::vector<uint8_t> key(32);
            std::size_t key_size = key.size();
            if (!context || EVP_PKEY_derive_init(context.get()) <= 0 ||
                EVP_PKEY_CTX_set_hkdf_md(context.get(), EVP_sha3_512()) <= 0 ||
                EVP_PKEY_CTX_set1_hkdf_salt(context.get(), sid.data(), sid.size()) <= 0 ||
                EVP_PKEY_CTX_set1_hkdf_key(context.get(), entropy.data(), entropy.size()) <= 0 ||
                EVP_PKEY_CTX_add1_hkdf_info(context.get(),
                    reinterpret_cast<const unsigned char*>(label.data()), label.size()) <= 0 ||
                EVP_PKEY_derive(context.get(), key.data(), &key_size) <= 0) {
                throw std::runtime_error("rekey derivation failed");
            }
            key.resize(key_size);
            return key;
        };
        auto send_key = derive("pqvpn-send");
        auto recv_key = derive("pqvpn-recv");
        last_rekey[new_sid] = std::chrono::duration<double>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return {new_sid, send_key, recv_key};
    }
};

} // namespace pqvpn

#endif // PQVPN_REKEY_MANAGER_HPP
