#ifndef PQVPN_CRYPTO_SIGNATURE_HPP
#define PQVPN_CRYPTO_SIGNATURE_HPP

#include <vector>
#include <string>
#include <optional>
#include <cstdint>

namespace pqvpn {

/**
 * Verify a signature using the nested oqs implementation.
 *
 * This simplified verifier expects the oqs nested module available (imported
 * as `oqs_module` earlier). It normalizes public key and signature inputs
 * (accepting hex/base64/bytes) and calls Signature.verify(message, signature, public_key).
 *
 * Returns True on successful verification, False otherwise.
 */
bool pq_sig_verify(
    const std::vector<uint8_t>& pk,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& sig,
    const std::optional<std::string>& alg = std::nullopt);

/**
 * Helper function to normalize input (bytes, hex strings, base64 strings)
 */
std::optional<std::vector<uint8_t>> pq_sig_normalize(const std::string& b);

} // namespace pqvpn

#endif // PQVPN_CRYPTO_SIGNATURE_HPP