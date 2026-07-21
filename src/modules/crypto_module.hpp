#ifndef PQVPN_CRYPTO_MODULE_HPP
#define PQVPN_CRYPTO_MODULE_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <random>
#include <algorithm>
#include <span>
#include <optional>
#include <memory>
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <oqs/oqs.h>
#include "logging_module.hpp"

namespace pqvpn::crypto {

struct KEMKeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
};

struct KEMResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> shared_secret;
};

struct SigKeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
};

struct X25519KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

class X25519 {
public:
    static X25519KeyPair keygen() {
        EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!raw_context) throw std::runtime_error("X25519 context creation failed");
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(raw_context, EVP_PKEY_CTX_free);
        EVP_PKEY* raw_key = nullptr;
        if (EVP_PKEY_keygen_init(context.get()) <= 0 || EVP_PKEY_keygen(context.get(), &raw_key) <= 0) {
            throw std::runtime_error("X25519 key generation failed");
        }
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);
        X25519KeyPair result{{}, {}};
        result.public_key.resize(32);
        result.private_key.resize(32);
        std::size_t public_size = result.public_key.size();
        std::size_t private_size = result.private_key.size();
        if (EVP_PKEY_get_raw_public_key(key.get(), result.public_key.data(), &public_size) <= 0 ||
            EVP_PKEY_get_raw_private_key(key.get(), result.private_key.data(), &private_size) <= 0) {
            throw std::runtime_error("X25519 raw key export failed");
        }
        return result;
    }

    static std::vector<uint8_t> derive(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key) {
        if (private_key.size() != 32 || peer_public_key.size() != 32) {
            throw std::invalid_argument("X25519 keys must be 32 bytes");
        }
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> local(
            EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size()), EVP_PKEY_free);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> peer(
            EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public_key.data(), peer_public_key.size()), EVP_PKEY_free);
        if (!local || !peer) throw std::runtime_error("X25519 key import failed");
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
            EVP_PKEY_CTX_new(local.get(), nullptr), EVP_PKEY_CTX_free);
        std::size_t secret_size = 0;
        if (!context || EVP_PKEY_derive_init(context.get()) <= 0 ||
            EVP_PKEY_derive_set_peer(context.get(), peer.get()) <= 0 ||
            EVP_PKEY_derive(context.get(), nullptr, &secret_size) <= 0) {
            throw std::runtime_error("X25519 derivation setup failed");
        }
        std::vector<uint8_t> secret(secret_size);
        if (EVP_PKEY_derive(context.get(), secret.data(), &secret_size) <= 0) {
            throw std::runtime_error("X25519 derivation failed");
        }
        secret.resize(secret_size);
        return secret;
    }
};

class KEM {
public:
    enum class Algorithm { Kyber1024 };
    static inline bool OQS_AVAILABLE = true;
    explicit KEM(Algorithm alg = Algorithm::Kyber1024) : alg_(alg) {}

    static KEMKeyPair keygen(Algorithm alg = Algorithm::Kyber1024) {
        auto kem = make_kem(alg);
        KEMKeyPair keys;
        keys.public_key.resize(kem->length_public_key);
        keys.secret_key.resize(kem->length_secret_key);
        if (OQS_KEM_keypair(kem.get(), keys.public_key.data(), keys.secret_key.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_KEM_keypair failed for ML-KEM-1024");
        }
        return keys;
    }

    static KEMResult encaps(const std::vector<uint8_t>& pk, Algorithm alg = Algorithm::Kyber1024) {
        auto kem = make_kem(alg);
        if (pk.size() != kem->length_public_key) {
            throw std::invalid_argument("ML-KEM-1024 public key has invalid length");
        }
        KEMResult result;
        result.ciphertext.resize(kem->length_ciphertext);
        result.shared_secret.resize(kem->length_shared_secret);
        if (OQS_KEM_encaps(kem.get(), result.ciphertext.data(), result.shared_secret.data(), pk.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_KEM_encaps failed for ML-KEM-1024");
        }
        return result;
    }

    static std::vector<uint8_t> decaps(const std::vector<uint8_t>& ct, const std::vector<uint8_t>& sk, Algorithm alg = Algorithm::Kyber1024) {
        auto kem = make_kem(alg);
        if (ct.size() != kem->length_ciphertext) {
            throw std::invalid_argument("ML-KEM-1024 ciphertext has invalid length");
        }
        if (sk.size() != kem->length_secret_key) {
            throw std::invalid_argument("ML-KEM-1024 secret key has invalid length");
        }
        std::vector<uint8_t> shared_secret(kem->length_shared_secret);
        if (OQS_KEM_decaps(kem.get(), shared_secret.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
            throw std::runtime_error("OQS_KEM_decaps failed for ML-KEM-1024");
        }
        return shared_secret;
    }

    static std::vector<uint8_t> serialize_private_key(EVP_PKEY* pkey) {
        if (!pkey) throw std::runtime_error("Null PKEY");
        BIO* bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PKCS8PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            std::vector<uint8_t> buffer(8192);
            int bytes = BIO_read(bio, buffer.data(), 8192);
            BIO_free(bio);
            if (bytes > 0) return std::vector<uint8_t>(buffer.begin(), buffer.begin() + bytes);
        }
        BIO_free(bio);
        throw std::runtime_error("Serialization failed");
    }

    static size_t buffer_size_limit() { return 8192; }
    Algorithm alg_;

private:
    struct OqsKemDeleter {
        void operator()(OQS_KEM* kem) const noexcept { OQS_KEM_free(kem); }
    };

    static std::unique_ptr<OQS_KEM, OqsKemDeleter> make_kem(Algorithm) {
        if (!OQS_AVAILABLE) {
            throw std::runtime_error("liboqs not available");
        }
        OQS_KEM* raw = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
        if (!raw) {
            raw = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
        }
        if (!raw) {
            throw std::runtime_error("liboqs ML-KEM-1024/Kyber1024 KEM unavailable");
        }
        return std::unique_ptr<OQS_KEM, OqsKemDeleter>(raw);
    }

};

inline std::vector<unsigned char> argon2_derive_key_material(const std::string& password, const std::vector<unsigned char>& salt, size_t output_len, uint32_t iterations = 3, uint32_t memcost = (1 << 16), uint32_t lanes = 1) {
    if (salt.size() < 8) throw std::invalid_argument("Argon2id salt must contain at least 8 bytes");
    std::vector<unsigned char> output(output_len);
    if (password.empty() && salt.empty()) return output;

#ifdef HAVE_ARGON2
    int res = argon2id_hash_raw(iterations, memcost, lanes, password.c_str(), password.length(),
                                 salt.data(), salt.size(), output.data(), output.size());
    if (res != ARGON2_OK) {
        throw std::runtime_error(std::string("Argon2id KDF failed: ") + argon2_error_message(res));
    }
#else
    throw std::runtime_error("Argon2id KDF unavailable: HAVE_ARGON2 not defined");
#endif

    return output;
}

inline std::vector<uint8_t> base32_encode(const std::vector<uint8_t>& input) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::vector<uint8_t> output;
    if (input.empty()) return output;

    for (size_t i = 0; i < input.size(); i += 5) {
        uint32_t chunk = 0;
        int bits_to_process = std::min<int>(5, (int)(input.size() - i));
        for (int j = 0; j < bits_to_process; ++j) {
            chunk |= static_cast<uint32_t>(input[i + j]) << (8 * (bits_to_process - 1 - j));
        }
        output.push_back(static_cast<uint8_t>(alphabet[chunk % alphabet.size()]));
    }
    return output;
}

} // namespace pqvpn::crypto

#endif // PQVPN_CRYPTO_MODULE_HPP
