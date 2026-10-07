#pragma once

// Persistent PQVPN node identity: Ed25519 (authentication), long-term X25519
// (classical DH half of the hybrid handshake), ML-KEM-1024 (post-quantum KEM)
// and ML-DSA-87 (post-quantum signatures). The key material is generated once
// per node, stored as hex JSON next to the configuration file with 0600 mode,
// and reloaded on every start so a peer's identity is stable across restarts.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef __unix__
#include <sys/stat.h>
#endif

#include <nlohmann/json.hpp>

#include "crypto_module.hpp" // X25519, KEM (ML-KEM-1024)
#include "hybrid_auth.hpp"   // ed25519_keygen
#include "../crypto_utils.hpp" // pq_sig_keygen (ML-DSA-87)

namespace pqvpn::identity {

inline std::string to_hex(const std::vector<uint8_t>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0f]);
    }
    return out;
}

inline std::optional<std::vector<uint8_t>> from_hex(const std::string& value) {
    if (value.empty() || value.size() % 2 != 0) return std::nullopt;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const int hi = nibble(value[i]);
        const int lo = nibble(value[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

struct NodeIdentity {
    std::vector<uint8_t> ed25519_sk;
    std::vector<uint8_t> ed25519_pk;
    std::vector<uint8_t> x25519_sk;
    std::vector<uint8_t> x25519_pk;
    std::vector<uint8_t> ml_kem_pk;
    std::vector<uint8_t> ml_kem_sk;
    std::vector<uint8_t> mldsa_pk;
    std::vector<uint8_t> mldsa_sk;

    static NodeIdentity generate() {
        NodeIdentity identity;
        const auto ed = crypto::ed25519_keygen();
        identity.ed25519_sk = ed.private_key;
        identity.ed25519_pk = ed.public_key;
        const auto x = crypto::X25519::keygen();
        identity.x25519_sk = x.private_key;
        identity.x25519_pk = x.public_key;
        const auto kem = crypto::KEM::keygen(crypto::KEM::Algorithm::Kyber1024);
        identity.ml_kem_pk = kem.public_key;
        identity.ml_kem_sk = kem.secret_key;
        const auto sig = pq_sig_keygen(); // ML-DSA-87
        identity.mldsa_pk = sig.public_key;
        identity.mldsa_sk = sig.secret_key;
        return identity;
    }

    void save(const std::string& path) const {
        nlohmann::json document = {
            {"version", 1},
            {"ed25519_sk", to_hex(ed25519_sk)},
            {"ed25519_pk", to_hex(ed25519_pk)},
            {"x25519_sk", to_hex(x25519_sk)},
            {"x25519_pk", to_hex(x25519_pk)},
            {"ml_kem_pk", to_hex(ml_kem_pk)},
            {"ml_kem_sk", to_hex(ml_kem_sk)},
            {"mldsa_pk", to_hex(mldsa_pk)},
            {"mldsa_sk", to_hex(mldsa_sk)},
        };
        const std::string temporary = path + ".tmp";
        {
            std::ofstream output(temporary, std::ios::trunc | std::ios::binary);
            if (!output) throw std::runtime_error("cannot open node identity file for writing");
            output << document.dump(2) << '\n';
        }
#ifdef __unix__
        ::chmod(temporary.c_str(), 0600);
#endif
        std::filesystem::rename(temporary, path);
    }

    static NodeIdentity load(const std::string& path) {
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("cannot open node identity file: " + path);
        const auto document = nlohmann::json::parse(input);
        auto field = [&](const char* name) -> std::vector<uint8_t> {
            const auto value = from_hex(document.value(name, std::string{}));
            if (!value || value->empty()) throw std::runtime_error(std::string("node identity missing ") + name);
            return *value;
        };
        NodeIdentity identity;
        identity.ed25519_sk = field("ed25519_sk");
        identity.ed25519_pk = field("ed25519_pk");
        identity.x25519_sk = field("x25519_sk");
        identity.x25519_pk = field("x25519_pk");
        identity.ml_kem_pk = field("ml_kem_pk");
        identity.ml_kem_sk = field("ml_kem_sk");
        identity.mldsa_pk = field("mldsa_pk");
        identity.mldsa_sk = field("mldsa_sk");
        return identity;
    }
};

} // namespace pqvpn::identity
