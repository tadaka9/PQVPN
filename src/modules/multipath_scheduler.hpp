#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pqvpn::multipath {

struct PathState {
    std::string peer_id;
    std::uint32_t rtt_ms = 1;
    std::uint32_t loss_ppm = 0;
    std::uint64_t capacity_bps = 1;
    std::uint32_t inflight = 0;
    std::uint32_t congestion_window = 10;
    bool live = true;
};

// Stable, keyed FNV-1a is used only for scheduling. It is not a security hash.
inline std::uint64_t schedule_hash(std::string_view flow, std::string_view peer) {
    std::uint64_t value = 1469598103934665603ULL;
    for (const char byte : flow) { value ^= static_cast<unsigned char>(byte); value *= 1099511628211ULL; }
    value ^= 0xff;
    for (const char byte : peer) { value ^= static_cast<unsigned char>(byte); value *= 1099511628211ULL; }
    return value;
}

inline std::vector<std::string> rank_paths(std::string_view flow, std::span<const PathState> paths) {
    struct Ranked { long double score; std::string peer; };
    std::vector<Ranked> ranked;
    for (const auto& path : paths) {
        if (!path.live || path.peer_id.empty() || path.inflight >= path.congestion_window ||
            path.loss_ppm >= 1'000'000 || path.capacity_bps == 0) continue;
        const auto entropy = static_cast<long double>(schedule_hash(flow, path.peer_id)) /
            static_cast<long double>(std::numeric_limits<std::uint64_t>::max());
        const auto health = static_cast<long double>(1'000'000 - path.loss_ppm) * path.capacity_bps /
            (static_cast<long double>(path.rtt_ms) + 1.0L);
        ranked.push_back({entropy * health, path.peer_id});
    }
    std::sort(ranked.begin(), ranked.end(), [](const auto& left, const auto& right) {
        return left.score != right.score ? left.score > right.score : left.peer < right.peer;
    });
    std::vector<std::string> result;
    for (const auto& item : ranked) result.push_back(item.peer);
    return result;
}

class ReorderBuffer {
public:
    explicit ReorderBuffer(std::uint64_t next = 0, std::size_t max_packets = 256,
                           std::size_t max_bytes = 2 * 1024 * 1024)
        : next_(next), max_packets_(max_packets), max_bytes_(max_bytes) {}

    std::optional<std::vector<std::vector<std::uint8_t>>> insert(
        std::uint64_t sequence, std::vector<std::uint8_t> payload) {
        if (payload.empty() || sequence < next_ || sequence - next_ >= max_packets_ ||
            packets_.contains(sequence) || payload.size() > max_bytes_ - bytes_) return std::nullopt;
        bytes_ += payload.size();
        packets_.emplace(sequence, std::move(payload));
        std::vector<std::vector<std::uint8_t>> ready;
        auto found = packets_.find(next_);
        while (found != packets_.end()) {
            bytes_ -= found->second.size();
            ready.push_back(std::move(found->second));
            packets_.erase(found);
            ++next_;
            found = packets_.find(next_);
        }
        return ready;
    }
    std::uint64_t next_sequence() const { return next_; }
    std::size_t buffered_packets() const { return packets_.size(); }
    std::size_t buffered_bytes() const { return bytes_; }
private:
    std::uint64_t next_;
    std::size_t max_packets_, max_bytes_, bytes_ = 0;
    std::map<std::uint64_t, std::vector<std::uint8_t>> packets_;
};

} // namespace pqvpn::multipath
