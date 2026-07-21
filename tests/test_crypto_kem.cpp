#include <catch2/catch_test_macros.hpp>
#include "crypto_module.hpp"

TEST_CASE("KEM Key Generation (OQS Mode)", "[crypto][kem]") {
    using namespace pqvpn::crypto;
    KEM::OQS_AVAILABLE = true;

    SECTION("Kyber1024/ML-KEM-1024 keygen produces non-empty keys") {
        auto keys = KEM::keygen(KEM::Algorithm::Kyber1024);
        REQUIRE_FALSE(keys.public_key.empty());
        REQUIRE_FALSE(keys.secret_key.empty());
    }
}

TEST_CASE("KEM Key Generation (Fallback/Error Mode)", "[crypto][kem]") {
    using namespace pqvpn::crypto;
    KEM::OQS_AVAILABLE = false;

    SECTION("Kyber1024/ML-KEM-1024 keygen throws when liboqs missing") {
        REQUIRE_THROWS_AS(KEM::keygen(KEM::Algorithm::Kyber1024), std::runtime_error);
    }
    KEM::OQS_AVAILABLE = true;
}

TEST_CASE("KEM Encapsulation (OQS Mode)", "[crypto][kem]") {
    using namespace pqvpn::crypto;
    KEM::OQS_AVAILABLE = true;
    auto keys = KEM::keygen(KEM::Algorithm::Kyber1024);

    SECTION("Encaps produces correct ciphertext and shared secret sizes") {
        auto result = KEM::encaps(keys.public_key, KEM::Algorithm::Kyber1024);
        REQUIRE_FALSE(result.ciphertext.empty());
        REQUIRE(result.shared_secret.size() == 32);
    }
}

TEST_CASE("KEM Decapsulation (OQS Mode)", "[crypto][kem]") {
    using namespace pqvpn::crypto;
    KEM::OQS_AVAILABLE = true;
    auto keys = KEM::keygen(KEM::Algorithm::Kyber1024);
    auto encap_res = KEM::encaps(keys.public_key, KEM::Algorithm::Kyber1024);

    SECTION("Decaps reproduces encapsulated shared secret") {
        auto ss = KEM::decaps(encap_res.ciphertext, keys.secret_key, KEM::Algorithm::Kyber1024);
        REQUIRE(ss.size() == 32);
        REQUIRE(ss == encap_res.shared_secret);
    }

    SECTION("Decaps throws when liboqs missing") {
        KEM::OQS_AVAILABLE = false;
        REQUIRE_THROWS_AS(KEM::decaps(encap_res.ciphertext, keys.secret_key, KEM::Algorithm::Kyber1024), std::runtime_error);
        KEM::OQS_AVAILABLE = true;
    }
}
