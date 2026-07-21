#include <catch2/catch_test_macros.hpp>
#include "crypto_kem.hpp"
#include "crypto_module.hpp"  // For KEM::OQS_AVAILABLE flag
#include <stdexcept>

TEST_CASE("KEM Key Generation - Exact Python Match", "[crypto][kem]") {
    using namespace pqvpn::crypto;

    SECTION("Should throw when OQS not available (matching exact Python error message)") {
        KEM::OQS_AVAILABLE = false;
        REQUIRE_THROWS_AS(pq_kem_keygen(), std::runtime_error);

        try {
            pq_kem_keygen();
        } catch (const std::runtime_error& e) {
            std::string error_msg = e.what();
            REQUIRE(error_msg.find("liboqs not available") != std::string::npos);
            REQUIRE(error_msg.find("hybrid-only mode requires liboqs") != std::string::npos);
        }
        KEM::OQS_AVAILABLE = true;
    }

    SECTION("Should generate valid key pair when OQS is available") {
        KEM::OQS_AVAILABLE = true;
        auto keys = pq_kem_keygen();
        REQUIRE_FALSE(keys.public_key.empty());
        REQUIRE_FALSE(keys.secret_key.empty());
    }
}
