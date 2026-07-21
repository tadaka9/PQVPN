#include <catch2/catch_test_macros.hpp>
#include "string_utils.hpp"
#include <string>

TEST_CASE("normalize_sig_config_name performs correct normalization", "[utils][string]") {
    using pqvpn::utils::normalize_sig_config_name;

    SECTION("Empty input returns default mldsa87") {
        CHECK(normalize_sig_config_name("") == "mldsa87");
    }

    SECTION("Standard algorithm names are normalized to lowercase alphanumeric") {
        CHECK(normalize_sig_config_name("ML-DSA-87") == "mldsa87");
        CHECK(normalize_sig_config_name("Kyber1024") == "kyber1024");
    }

    SECTION("Special characters are stripped") {
        CHECK(normalize_sig_config_name("ML-DSA_87!") == "mldsa87");
        CHECK(normalize_sig_config_name("  ML-DSA-87  ") == "mldsa87");
        CHECK(normalize_sig_config_name("Algorithm@Name#123") == "algorithmname123");
    }

    SECTION("Non-alphanumeric only input strips to empty like Python") {
        CHECK(normalize_sig_config_name("!!!").empty());
    }
}
