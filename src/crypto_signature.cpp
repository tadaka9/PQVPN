#include "crypto_signature.hpp"
#include "crypto_utils.hpp"
#include <vector>
#include <string>
#include <optional>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <memory>
#include <oqs/oqs.h>

namespace pqvpn {

bool pq_sig_verify(
    const std::vector<uint8_t>& pk,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& sig,
    const std::optional<std::string>& alg)
{
    if (pk.empty() || sig.empty()) {
        return false;
    }
    if (alg.value_or("ML-DSA-87") != "ML-DSA-87") {
        return false;
    }
    const auto deleter = [](OQS_SIG* value) { OQS_SIG_free(value); };
    std::unique_ptr<OQS_SIG, decltype(deleter)> verifier(OQS_SIG_new(OQS_SIG_alg_ml_dsa_87), deleter);
    if (!verifier || pk.size() != verifier->length_public_key || sig.size() > verifier->length_signature) {
        return false;
    }
    return OQS_SIG_verify(verifier.get(), data.data(), data.size(), sig.data(), sig.size(), pk.data()) == OQS_SUCCESS;
}

} // namespace pqvpn
