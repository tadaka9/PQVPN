#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>

#include "crypto_signature.hpp"
#include "crypto_utils.hpp"
#include "hybrid_kdf.hpp"

namespace pqvpn::crypto {

struct Ed25519KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

struct HybridSignature {
    std::vector<uint8_t> ed25519;
    std::vector<uint8_t> ml_dsa_87;
};

inline Ed25519KeyPair ed25519_keygen() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* raw_key = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
        EVP_PKEY_keygen(context.get(), &raw_key) <= 0) {
        throw std::runtime_error("Ed25519 key generation failed");
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);
    Ed25519KeyPair result{{}, {}};
    result.public_key.resize(32);
    result.private_key.resize(32);
    std::size_t public_size = result.public_key.size();
    std::size_t private_size = result.private_key.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), result.public_key.data(), &public_size) <= 0 ||
        EVP_PKEY_get_raw_private_key(key.get(), result.private_key.data(), &private_size) <= 0) {
        throw std::runtime_error("Ed25519 key export failed");
    }
    return result;
}

inline std::vector<uint8_t> ed25519_sign(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& message) {
    if (private_key.size() != 32) throw std::invalid_argument("Ed25519 private key must be 32 bytes");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size()), EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    std::size_t signature_size = 0;
    if (!key || !context || EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) <= 0 ||
        EVP_DigestSign(context.get(), nullptr, &signature_size, message.data(), message.size()) <= 0) {
        throw std::runtime_error("Ed25519 signing setup failed");
    }
    std::vector<uint8_t> signature(signature_size);
    if (EVP_DigestSign(context.get(), signature.data(), &signature_size, message.data(), message.size()) <= 0) {
        throw std::runtime_error("Ed25519 signing failed");
    }
    signature.resize(signature_size);
    return signature;
}

inline bool ed25519_verify(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature) {
    if (public_key.size() != 32 || signature.size() != 64) return false;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size()), EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    return key && context &&
        EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) > 0 &&
        EVP_DigestVerify(context.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
}

inline HybridSignature sign_hybrid_transcript(
    const std::vector<uint8_t>& transcript,
    const std::vector<uint8_t>& ed25519_private_key,
    const std::vector<uint8_t>& ml_dsa_private_key) {
    if (transcript.empty()) throw std::invalid_argument("handshake transcript cannot be empty");
    const auto digest = sha3_512(transcript);
    return {ed25519_sign(ed25519_private_key, digest), pq_sig_sign(ml_dsa_private_key, digest)};
}

inline bool verify_hybrid_transcript(
    const std::vector<uint8_t>& transcript,
    const std::vector<uint8_t>& ed25519_public_key,
    const std::vector<uint8_t>& ml_dsa_public_key,
    const HybridSignature& signature) {
    if (transcript.empty()) return false;
    const auto digest = sha3_512(transcript);
    return ed25519_verify(ed25519_public_key, digest, signature.ed25519) &&
        pq_sig_verify(ml_dsa_public_key, digest, signature.ml_dsa_87);
}

} // namespace pqvpn::crypto
