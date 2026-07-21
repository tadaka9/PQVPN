#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace pqvpn::crypto {

inline std::vector<uint8_t> sha3_512(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> digest(64);
    unsigned int digest_size = 0;
    if (EVP_Digest(input.data(), input.size(), digest.data(), &digest_size,
                   EVP_sha3_512(), nullptr) != 1 || digest_size != digest.size()) {
        throw std::runtime_error("SHA3-512 digest failed");
    }
    return digest;
}

inline std::vector<uint8_t> combine_hybrid_secrets(
    const std::vector<uint8_t>& x25519_secret,
    const std::vector<uint8_t>& ml_kem_secret,
    const std::vector<uint8_t>& handshake_transcript,
    const std::size_t output_size = 32) {
    if (x25519_secret.size() != 32 || ml_kem_secret.empty() ||
        handshake_transcript.empty() || output_size == 0) {
        throw std::invalid_argument("hybrid KDF requires both secrets, a transcript, and nonzero output");
    }

    std::vector<uint8_t> input_key_material;
    input_key_material.reserve(x25519_secret.size() + ml_kem_secret.size());
    input_key_material.insert(input_key_material.end(), x25519_secret.begin(), x25519_secret.end());
    input_key_material.insert(input_key_material.end(), ml_kem_secret.begin(), ml_kem_secret.end());
    const auto transcript_digest = sha3_512(handshake_transcript);
    static constexpr std::string_view context = "PQVPN hybrid handshake v1";

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kdf(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    std::vector<uint8_t> output(output_size);
    std::size_t derived_size = output.size();
    if (!kdf || EVP_PKEY_derive_init(kdf.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(kdf.get(), EVP_sha3_512()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(kdf.get(), transcript_digest.data(), transcript_digest.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(kdf.get(), input_key_material.data(), input_key_material.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(kdf.get(),
            reinterpret_cast<const unsigned char*>(context.data()), context.size()) <= 0 ||
        EVP_PKEY_derive(kdf.get(), output.data(), &derived_size) <= 0) {
        throw std::runtime_error("HKDF-SHA3-512 hybrid derivation failed");
    }
    output.resize(derived_size);
    return output;
}

} // namespace pqvpn::crypto
