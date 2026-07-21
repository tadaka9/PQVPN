#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <ctime>
#include <vector>

extern "C" void argon2_derive_key_lib(
    const uint8_t*, size_t, const uint8_t*, size_t,
    uint32_t, uint32_t, uint32_t, uint32_t hash_len, uint8_t* out) {
    for (size_t i = 0; i < hash_len; ++i) out[i] = 0;
}

#include "key_rotation_module.hpp"

TEST_CASE("KeyRotationManager initializes deterministic policy defaults") {
    pqvpn::crypto::KeyRotationManager manager;
    CHECK(manager.get_rekey_interval_hours() == 4.0);
    CHECK(manager.get_rekey_interval_gb() == 100.0);
    CHECK(manager.get_last_rekey_count() == 0);
}

TEST_CASE("KeyRotationManager evaluates time and traffic thresholds") {
    pqvpn::crypto::KeyRotationManager manager;
    const std::vector<uint8_t> session_id{1, 2, 3, 4};
    const double now = static_cast<double>(std::time(nullptr));

    CHECK_FALSE(manager.should_rekey(session_id, 0.0, now));
    CHECK(manager.should_rekey(session_id, 0.0, now - 4.0 * 3600.0));
    CHECK(manager.should_rekey(session_id, 100.0 * 1e9, now));
}
