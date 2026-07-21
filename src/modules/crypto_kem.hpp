#ifndef PQVPN_CRYPTO_KEM_HPP
#define PQVPN_CRYPTO_KEM_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <optional>
#include <cstdint>
#include "crypto_module.hpp"

namespace pqvpn::crypto {

/**
 * Generate Kyber KEM key pair.
 *
 * If liboqs-python is available use it; otherwise provide a lightweight
 * fallback that returns random-length keys suitable for unit tests.
 */
KEMKeyPair pq_kem_keygen();

} // namespace pqvpn::crypto

#endif // PQVPN_CRYPTO_KEM_HPP
