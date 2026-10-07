#ifndef PQVPN_TUNNEL_AEAD_HPP
#define PQVPN_TUNNEL_AEAD_HPP

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>

namespace pqvpn {

// Tunnel AEAD primitives shared by the direct data path (build_tunnel_datagram /
// datagram_received) and the relay onion path (handle_relay). The wire contract
// mirrors main.py: a 12-byte nonce is the session's random 4-byte IV prefix
// followed by an 8-byte big-endian counter, and payloads are sealed with
// AES-128-GCM or AES-256-GCM (selected by key size) with the 16-byte tag
// appended to the ciphertext. Known-answer vectors for these exact functions
// live in tests/test_tunnel_aead_kat.cpp.

inline std::vector<uint8_t> tunnel_nonce(const std::vector<uint8_t>& iv, const uint64_t counter) {
    if (iv.size() != 12 || counter == 0) {
        throw std::invalid_argument("tunnel session has invalid nonce state");
    }
    std::vector<uint8_t> nonce(12);
    std::copy_n(iv.begin(), 4, nonce.begin());
    for (std::size_t index = 0; index < 8; ++index) {
        nonce[4 + index] = static_cast<uint8_t>(counter >> (56 - index * 8));
    }
    return nonce;
}

inline std::vector<uint8_t> tunnel_encrypt(
    const std::span<const uint8_t> plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::span<const uint8_t> aad) {
    const EVP_CIPHER* cipher = key.size() == 16 ? EVP_aes_128_gcm() :
        key.size() == 32 ? EVP_aes_256_gcm() : nullptr;
    if (!cipher || nonce.size() != 12) throw std::invalid_argument("invalid tunnel AEAD material");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) throw std::runtime_error("tunnel AEAD context allocation failed");

    std::vector<uint8_t> output(plaintext.size() + 16);
    int ignored = 0;
    int written = 0;
    int final_written = 0;
    if (EVP_EncryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_EncryptUpdate(context.get(), nullptr, &ignored, aad.data(), static_cast<int>(aad.size())) != 1 ||
        EVP_EncryptUpdate(context.get(), output.data(), &written, plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(context.get(), output.data() + written, &final_written) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, 16, output.data() + written + final_written) != 1) {
        throw std::runtime_error("tunnel AEAD encryption failed");
    }
    output.resize(static_cast<std::size_t>(written + final_written) + 16);
    return output;
}

inline std::optional<std::vector<uint8_t>> tunnel_decrypt(
    const std::span<const uint8_t> ciphertext_and_tag,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::span<const uint8_t> aad) {
    if (ciphertext_and_tag.size() < 16) return std::nullopt;
    const EVP_CIPHER* cipher = key.size() == 16 ? EVP_aes_128_gcm() :
        key.size() == 32 ? EVP_aes_256_gcm() : nullptr;
    if (!cipher || nonce.size() != 12) return std::nullopt;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) return std::nullopt;

    const auto ciphertext_size = ciphertext_and_tag.size() - 16;
    std::vector<uint8_t> plaintext(ciphertext_size);
    int ignored = 0;
    int written = 0;
    int final_written = 0;
    if (EVP_DecryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &ignored, aad.data(), static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(context.get(), plaintext.data(), &written, ciphertext_and_tag.data(), static_cast<int>(ciphertext_size)) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, 16,
            const_cast<uint8_t*>(ciphertext_and_tag.data() + ciphertext_size)) != 1 ||
        EVP_DecryptFinal_ex(context.get(), plaintext.data() + written, &final_written) != 1) {
        return std::nullopt;
    }
    plaintext.resize(static_cast<std::size_t>(written + final_written));
    return plaintext;
}

} // namespace pqvpn

#endif // PQVPN_TUNNEL_AEAD_HPP
