#include "ml_traffic_shaper.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>
#include <stdexcept>
#include <openssl/rand.h>

namespace pqvpn::traffic {
namespace {
double prediction(const std::array<double, 3>& weights, const std::array<double, 3>& features) {
    return std::clamp(std::inner_product(weights.begin(), weights.end(), features.begin(), 0.0), 0.0, 1.0);
}
void learn(std::array<double, 3>& weights, const std::array<double, 3>& features, double target) {
    const double error = target - prediction(weights, features);
    for (std::size_t i = 0; i < weights.size(); ++i)
        weights[i] = std::clamp(weights[i] + 0.05 * error * features[i], -2.0, 2.0);
}
} // namespace

void TrafficModel::observe(std::size_t size, Clock::time_point now) {
    const double normalized_size = std::min(size / 1500.0, 1.0);
    const double gap = previous_ ? std::chrono::duration<double, std::milli>(now - *previous_).count() : 0.0;
    const double normalized_gap = std::clamp(gap / 100.0, 0.0, 1.0);
    if (previous_) {
        learn(size_weights_, features_, normalized_size);
        learn(gap_weights_, features_, normalized_gap);
    }
    features_ = {1, normalized_size, normalized_gap};
    previous_ = now;
    ++samples_;
}
double TrafficModel::predicted_size() const { return prediction(size_weights_, features_) * 1500; }
double TrafficModel::predicted_gap_ms() const { return prediction(gap_weights_, features_) * 100; }

MLTrafficShaper::MLTrafficShaper(asio::io_context& io, ShapingConfig config)
    : config_(config), timer_(io) {
    if (config.max_padding_bytes > 4096 || config.max_delay_ms < 0 || config.max_delay_ms > 100 ||
        config.max_queue_packets == 0 || config.max_queue_packets > 4096 ||
        config.max_queue_bytes < 1200 || config.max_queue_bytes > 16 * 1024 * 1024)
        throw std::invalid_argument("traffic shaping limits are out of range");
}

std::vector<uint8_t> MLTrafficShaper::pad(std::span<const uint8_t> packet) const {
    // UDP's maximum payload is 65507. Outer header + nonce + tag = 44 bytes.
    if (packet.empty() || packet.size() > 65507 - 44 - 3)
        throw std::length_error("packet does not fit the padded UDP envelope");
    const std::size_t minimum = packet.size() + 3;
    std::size_t target = minimum;
    const auto desired = std::max(minimum + 44, static_cast<std::size_t>(model_.predicted_size()) + 47);
    for (const std::size_t wire_bucket : {256U, 512U, 1024U, 1200U}) {
        const auto bucket = wire_bucket - 44;
        if (bucket >= minimum && bucket - minimum <= config_.max_padding_bytes) {
            target = bucket;
            if (wire_bucket >= desired) break;
        }
    }
    std::vector<uint8_t> result(target);
    result[0] = 1; // authenticated envelope version
    result[1] = static_cast<uint8_t>(packet.size() >> 8);
    result[2] = static_cast<uint8_t>(packet.size());
    std::copy(packet.begin(), packet.end(), result.begin() + 3);
    if (target > minimum && RAND_bytes(result.data() + minimum, static_cast<int>(target - minimum)) != 1)
        throw std::runtime_error("secure traffic padding generation failed");
    return result;
}

std::optional<std::vector<uint8_t>> MLTrafficShaper::unpad(std::span<const uint8_t> padded) {
    if (padded.size() < 3 || padded[0] != 1) return std::nullopt;
    const auto size = (static_cast<std::size_t>(padded[1]) << 8) | padded[2];
    if (size == 0 || size > padded.size() - 3) return std::nullopt;
    return std::vector<uint8_t>(padded.begin() + 3, padded.begin() + 3 + size);
}

bool MLTrafficShaper::enqueue(std::vector<uint8_t> frame, std::size_t original_size, Sender sender) {
    if (stopped_ || !sender || frame.empty() || queue_.size() >= config_.max_queue_packets ||
        frame.size() > config_.max_queue_bytes - queued_bytes_) {
        ++dropped_;
        return false;
    }
    const auto now = Clock::now();
    model_.observe(original_size, now);
    const int delay = std::min(config_.max_delay_ms,
        static_cast<int>(std::ceil(model_.predicted_gap_ms() / 5.0)) * 5);
    auto due = now + std::chrono::milliseconds(delay);
    if (!queue_.empty()) due = std::max(due, queue_.back().due);
    const bool first = queue_.empty();
    queued_bytes_ += frame.size();
    queue_.push_back({std::move(frame), std::move(sender), due});
    if (first) arm();
    return !stopped_;
}

void MLTrafficShaper::arm() {
    timer_.expires_at(queue_.front().due);
    timer_.async_wait([self = shared_from_this()](const asio::error_code& error) {
        if (error || self->stopped_) return;
        auto packet = std::move(self->queue_.front());
        self->queue_.pop_front();
        self->queued_bytes_ -= packet.frame.size();
        try {
            if (packet.sender(packet.frame)) ++self->sent_;
            else ++self->dropped_;
        } catch (...) { ++self->dropped_; }
        if (!self->queue_.empty() && !self->stopped_) self->arm();
    });
}
void MLTrafficShaper::stop() {
    stopped_ = true;
    timer_.cancel();
    dropped_ += queue_.size();
    queue_.clear();
    queued_bytes_ = 0;
}
} // namespace pqvpn::traffic
