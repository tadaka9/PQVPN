#define CATCH2_CONFIG_MAIN
#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include "../src/modules/crypto_module.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>

// Helper to generate an EC key for testing
EVP_PKEY* generate_ec_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) return nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int main() {
    try {
        std::cout << "Running ad-hoc verification for pqvpn::crypto::KEM::serialize_private_key..." << std::endl;

        // 1. Create an EC keypair using OpenSSL
        EVP_PKEY* pkey = generate_ec_key();
        if (!pkey) throw std::runtime_error("Failed to generate EC key");

        // 2. Test Serialization
        std::vector<uint8_t> serialized = pqvpn::crypto::KEM::serialize_private_key(pkey);

        if (serialized.empty()) {
            throw std::runtime_error("Serialization returned empty bytes");
        }

        std::string output(serialized.begin(), serialized.end());
        std::cout << "Serialized key size: " << serialized.size() << " bytes" << std::endl;

        // 3. Verify PEM headers exist in the output (standard for PKCS8/Traditional)
        if (output.find("-----BEGIN") == std::string::npos && output.find("-----END") == std::string::npos) {
             throw std::runtime_error("Serialization did not produce valid PEM format");
        }

        std::cout << "Verification SUCCESS: Private key serialized correctly." << std::endl;

        EVP_PKEY_free(pkey);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Verification FAILED: " << e.what() << std::endl;
        return 1;
    }
}
