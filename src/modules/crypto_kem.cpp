#include "crypto_kem.hpp"
#include "logging_module.hpp"
#include <vector>
#include <string>
#include <stdexcept>
#include <optional>
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Helper function to check if string contains only hex characters
bool is_hex_string(const std::string& s) {
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}

namespace pqvpn::crypto {

KEMKeyPair pq_kem_keygen() {
    if (!KEM::OQS_AVAILABLE) {
        throw std::runtime_error(
            "pq_kem_keygen: liboqs not available; hybrid-only mode requires liboqs"
        );
    }

    auto res = KEM::keygen(KEM::Algorithm::Kyber1024);

    std::vector<uint8_t> pk = res.public_key;
    std::vector<uint8_t> sk = res.secret_key;

    logging::Logger::debug("Kyber keypair generated - pk_len=" + std::to_string(pk.size()) + " sk_len=" + std::to_string(sk.size()));

    return {pk, sk};
}

} // namespace pqvpn::crypto
