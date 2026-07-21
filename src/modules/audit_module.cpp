#include "audit_module.hpp"
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <algorithm>

AuditTrail::AuditTrail() : last_hash(32, 0x00) {}

void AuditTrail::log_event(const std::string& event_type,
                           const std::vector<uint8_t>& peer_id,
                           const std::string& description) {
    double timestamp = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count()) / 1000000.0;

    // Construct event_data string: {event_type}{peer_id.hex()}{description}{timestamp}
    std::stringstream ss;
    ss << event_type;

    for (auto b : peer_id) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    ss << description << timestamp;
    std::string event_data = ss.str();

    // Compute SHA256(last_hash + event_data)
    std::vector<uint8_t> data_to_hash = last_hash;
    data_to_hash.insert(data_to_hash.end(), event_data.begin(), event_data.end());

    std::vector<uint8_t> new_hash(32);
    unsigned int hash_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) &&
            EVP_DigestUpdate(ctx, data_to_hash.data(), data_to_hash.size()) &&
            EVP_DigestFinal_ex(ctx, new_hash.data(), &hash_len)) {
            // Success
        }
        EVP_MD_CTX_free(ctx);
    }

    AuditLogEntry entry{
        timestamp,
        event_type,
        peer_id,
        description,
        new_hash
    };

    entries.push_back(entry);
    if (merkle_hashes.size() == MAX_HASHES) {
        merkle_hashes.pop_front();
    }
    merkle_hashes.push_back(new_hash);
    last_hash = new_hash;

    spdlog::debug("Audit: {} - {}", event_type, description);
}

bool AuditTrail::verify_integrity() const {
    if (entries.empty()) {
        return last_hash == std::vector<uint8_t>(32, 0x00);
    }

    std::vector<uint8_t> current_hash(32, 0x00);
    for (const auto& entry : entries) {
        std::stringstream ss;
        ss << entry.event_type;

        for (auto b : entry.peer_id) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }

        ss << entry.description << entry.timestamp;
        std::string event_data = ss.str();

        std::vector<uint8_t> data_to_hash = current_hash;
        data_to_hash.insert(data_to_hash.end(), event_data.begin(), event_data.end());

        std::vector<uint8_t> expected_hash(32);
        unsigned int hash_len = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx) {
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) &&
                EVP_DigestUpdate(ctx, data_to_hash.data(), data_to_hash.size()) &&
                EVP_DigestFinal_ex(ctx, expected_hash.data(), &hash_len)) {
                // Success
            }
            EVP_MD_CTX_free(ctx);
        }

        if (expected_hash != entry.hash_chain) {
            spdlog::error("Audit integrity check failed at {}", entry.timestamp);
            return false;
        }

        current_hash = expected_hash;
    }

    return current_hash == last_hash;
}
