#include <catch2/catch_test_macros.hpp>
#include "modules/crypto_agility.hpp"

using namespace pqvpn::crypto_agility;

TEST_CASE("crypto agility accepts only the compiled signed epoch", "[crypto][agility]") {
    Policy policy{.experimental_network = true};
    CHECK(negotiate(policy, {kHybridV1, kCompiledEpoch}).accepted);
    CHECK(negotiate(policy, {kHybridV1, 0}).rejection == Rejection::Rollback);
    CHECK(negotiate(policy, {kHybridV1, kCompiledEpoch + 1}).rejection == Rejection::FutureEpoch);
    CHECK(negotiate(policy, {"invented-cipher", kCompiledEpoch}).rejection == Rejection::UnsupportedSuite);
}

TEST_CASE("stable networks cannot expose an evolution window", "[crypto][agility]") {
    Policy policy{.minimum_epoch = 1, .maximum_epoch = 2, .experimental_network = false};
    CHECK(negotiate(policy, {kHybridV1, 1}).rejection == Rejection::ExperimentalOnStable);
}
