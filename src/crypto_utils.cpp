#include "crypto_utils.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <optional>
#include <algorithm>
#include <memory>
#include <oqs/oqs.h>

namespace pqvpn {

bool oqs_available() {
    return OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_87) != 0;
}

namespace {
struct SignatureDeleter {
    void operator()(OQS_SIG* signature) const noexcept { OQS_SIG_free(signature); }
};

std::unique_ptr<OQS_SIG, SignatureDeleter> make_signature(const std::string& algorithm) {
    if (algorithm != "ML-DSA-87") {
        throw std::invalid_argument("only ML-DSA-87 is supported");
    }
    auto signature = std::unique_ptr<OQS_SIG, SignatureDeleter>(OQS_SIG_new(OQS_SIG_alg_ml_dsa_87));
    if (!signature) {
        throw std::runtime_error("pq signature: liboqs ML-DSA-87 unavailable");
    }
    return signature;
}
} // namespace

std::vector<uint8_t> pq_sig_sign(
    const std::vector<uint8_t>& sk,
    const std::vector<uint8_t>& data,
    const std::string& alg)
{
    auto signature = make_signature(alg);
    if (sk.size() != signature->length_secret_key) {
        throw std::invalid_argument("ML-DSA-87 secret key has invalid length");
    }
    std::vector<uint8_t> result(signature->length_signature);
    std::size_t result_size = 0;
    if (OQS_SIG_sign(signature.get(), result.data(), &result_size, data.data(), data.size(), sk.data()) != OQS_SUCCESS) {
        throw std::runtime_error("OQS_SIG_sign failed for ML-DSA-87");
    }
    result.resize(result_size);
    return result;
}

bool is_hex_string(const std::string& s) {
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}

std::vector<uint8_t> hex_string_to_bytes(const std::string& hex) {
    std::vector<uint8_t> result;
    if (hex.length() % 2 != 0) return result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        try {
            result.push_back(static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16)));
        } catch (...) {
            return {};
        }
    }
    return result;
}

SigKeyPair pq_sig_keygen(const std::optional<std::string>& alg) {
    auto signature = make_signature(alg.value_or("ML-DSA-87"));
    SigKeyPair keys{{}, {}};
    keys.public_key.resize(signature->length_public_key);
    keys.secret_key.resize(signature->length_secret_key);
    if (OQS_SIG_keypair(signature.get(), keys.public_key.data(), keys.secret_key.data()) != OQS_SUCCESS) {
        throw std::runtime_error("OQS_SIG_keypair failed for ML-DSA-87");
    }
    return keys;
}

} // namespace pqvpn
