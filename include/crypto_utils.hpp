#ifndef PQVPN_CRYPTO_UTILS_HPP
#define PQVPN_CRYPTO_UTILS_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace pqvpn {
    /**
     * @brief Quantum-safe signature signing function (ML-DSA or other oqs signature)
     *
     * Signs data with the mandatory ML-DSA-87 provider.
     * when liboqs is not available.
     */
    std::vector<uint8_t> pq_sig_sign(
        const std::vector<uint8_t>& sk,
        const std::vector<uint8_t>& data,
        const std::string& alg = "ML-DSA-87"
    );

    /**
     * @brief Quantum-safe signature key generation function (ML-DSA or other oqs signature)
     *
     * This mimics the Python behavior of pq_sig_keygen with fallback to random
     * when liboqs is not available.
     */
    struct SigKeyPair {
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> secret_key;
    };

    /**
     * @brief Generate a signature key pair using quantum-safe algorithms (ML-DSA or other oqs signature)
     *
     * If OQS is not available, this will throw an exception as a fallback for testing.
     */
    SigKeyPair pq_sig_keygen(const std::optional<std::string>& alg = std::nullopt);

    /**
     * @brief Check if OQS (Open Quantum Safe) is available
     */
    bool oqs_available();
} // namespace pqvpn

#endif // PQVPN_CRYPTO_UTILS_HPP
