#ifndef PQVPN_CRYPTO_UTILS_HPP
#define PQVPN_CRYPTO_UTILS_HPP

#include <vector>
#include <string>
#include <optional>
#include <cstdint>

namespace pqvpn {

bool oqs_available();

std::vector<uint8_t> pq_sig_sign(
    const std::vector<uint8_t>& sk,
    const std::vector<uint8_t>& data,
    const std::string& alg);

struct SigKeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
};

SigKeyPair pq_sig_keygen(const std::optional<std::string>& alg = std::nullopt);

} // namespace pqvpn

#endif // PQVPN_CRYPTO_UTILS_HPP