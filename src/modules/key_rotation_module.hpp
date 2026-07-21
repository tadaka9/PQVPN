#ifndef KEY_ROTATION_MODULE_HPP
#define KEY_ROTATION_MODULE_HPP

#include <map>
#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <tuple>
#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>

namespace pqvpn::crypto {

class ChaCha20Poly1305Instance {
public:
    explicit ChaCha20Poly1305Instance(const std::vector<uint8_t>& key) : key_(key) {}
    const std::vector<uint8_t>& getKey() const { return key_; }
private:
    std::vector<uint8_t> key_;
};

extern "C" {
    void argon2_derive_key_lib(const uint8_t* password, size_t password_len,
                               const uint8_t* salt, size_t salt_len,
                               uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                               uint32_t hash_len, uint8_t* out);
}

class KeyRotationManager {
public:
    KeyRotationManager()
        : rekey_interval_hours_(4.0),
          rekey_interval_gb_(100.0) {}

    double get_rekey_interval_hours() const { return rekey_interval_hours_; }
    double get_rekey_interval_gb() const { return rekey_interval_gb_; }
    size_t get_last_rekey_count() const { return last_rekey_.size(); }

    bool should_rekey(const std::vector<uint8_t>& session_id, double bytes_transferred, double last_rekey_time) {
        double elapsed = static_cast<double>(std::time(nullptr)) - last_rekey_time;
        double elapsed_hours = elapsed / 3600.0;

        const bool expired = elapsed_hours >= rekey_interval_hours_;
        const bool exhausted = bytes_transferred >= rekey_interval_gb_ * 1e9;
        return expired || exhausted;
    }

    std::tuple<std::vector<uint8_t>, ChaCha20Poly1305Instance, ChaCha20Poly1305Instance> perform_rekey(const std::vector<uint8_t>& session_id) {
        std::vector<uint8_t> fresh_entropy(32);
        if (RAND_bytes(fresh_entropy.data(), static_cast<int>(fresh_entropy.size())) != 1) {
            throw std::runtime_error("secure random generation failed during key rotation");
        }

        // 2. Prepare salt (session_id[:16])
        std::vector<uint8_t> salt(16, 0x00);
        size_t copy_len = std::min(session_id.size(), (size_t)16);
        std::copy(session_id.begin(), session_id.begin() + copy_len, salt.begin());

        // 3. Derive send_key
        std::vector<uint8_t> send_key(32);
        for(size_t i=0; i<32; ++i) send_key[i] = fresh_entropy[i] ^ salt[i % 16];

        // 4. Derive recv_key (fresh_entropy + b"recv")
        std::vector<uint8_t> recv_key(32);
        const std::string recv_suffix = "recv";
        for(size_t i=0; i<32; ++i) {
            uint8_t suffix_byte = (i < recv_suffix.size()) ? static_cast<uint8_t>(recv_suffix[i]) : 0x00;
            recv_key[i] = fresh_entropy[i] ^ salt[i % 16] ^ suffix_byte;
        }

        // 5. Create AEAD instances
        ChaCha20Poly1305Instance aead_send(send_key);
        ChaCha20Poly1305Instance aead_recv(recv_key);

        // 6. Update last rekey time
        last_rekey_[session_id] = std::chrono::system_clock::now();

        return {session_id, aead_send, aead_recv};
    }

private:
    double rekey_interval_hours_;
    double rekey_interval_gb_;
    std::map<std::vector<uint8_t>, std::chrono::system_clock::time_point> last_rekey_;
};

} // namespace pqvpn::crypto

#endif // KEY_ROTATION_MODULE_HPP
