#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace pqvpn::crypto_agility {

inline constexpr const char* kHybridV1 = "pqvpn-hybrid-v1";
inline constexpr std::uint64_t kCompiledEpoch = 1;

struct Offer { std::string suite; std::uint64_t epoch = 0; };
struct Policy {
    std::string suite = kHybridV1;
    std::uint64_t minimum_epoch = kCompiledEpoch;
    std::uint64_t maximum_epoch = kCompiledEpoch;
    bool experimental_network = false;
};
enum class Rejection { EmptySuite, UnsupportedSuite, Rollback, FutureEpoch, ExperimentalOnStable };
struct Decision { bool accepted = false; std::optional<Rejection> rejection; };

inline Decision negotiate(const Policy& local, const Offer& peer) {
    if (peer.suite.empty()) return {false, Rejection::EmptySuite};
    if (peer.suite != kHybridV1 || peer.suite != local.suite)
        return {false, Rejection::UnsupportedSuite};
    if (peer.epoch < local.minimum_epoch) return {false, Rejection::Rollback};
    if (peer.epoch > local.maximum_epoch) return {false, Rejection::FutureEpoch};
    if (!local.experimental_network && local.minimum_epoch != local.maximum_epoch)
        return {false, Rejection::ExperimentalOnStable};
    return {true, std::nullopt};
}

} // namespace pqvpn::crypto_agility
