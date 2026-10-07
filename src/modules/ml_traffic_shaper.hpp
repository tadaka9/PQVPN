#pragma once

#include <array>
#include <cstdint>
#include <asio.hpp>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace pqvpn::traffic {

struct ShapingConfig {
    bool enabled = false;
    std::size_t max_padding_bytes = 1024;
    int max_delay_ms = 20;
    std::size_t max_queue_packets = 256;
    std::size_t max_queue_bytes = 512 * 1024;
};

// Online linear predictors trained by bounded SGD on local packet sizes and
// interarrival times. The model predicts workload, not an ISP's classifier.
// No payload inspection, external telemetry, model download or persistence.
class TrafficModel {
public:
    using Clock = std::chrono::steady_clock;
    void observe(std::size_t packet_size, Clock::time_point now);
    double predicted_size() const;
    double predicted_gap_ms() const;
    std::size_t samples() const { return samples_; }
private:
    std::array<double, 3> size_weights_{0.5, 0, 0};
    std::array<double, 3> gap_weights_{0.1, 0, 0};
    std::array<double, 3> features_{1, 0, 0};
    std::optional<Clock::time_point> previous_;
    std::size_t samples_ = 0;
};

class MLTrafficShaper : public std::enable_shared_from_this<MLTrafficShaper> {
public:
    using Clock = TrafficModel::Clock;
    using Sender = std::function<bool(const std::vector<uint8_t>&)>;
    MLTrafficShaper(asio::io_context& io, ShapingConfig config);
    std::vector<uint8_t> pad(std::span<const uint8_t> packet) const;
    static std::optional<std::vector<uint8_t>> unpad(std::span<const uint8_t> padded);
    // Returns acceptance into a bounded FIFO. A failed network send is
    // counted and dropped; it never triggers an unshaped retry.
    bool enqueue(std::vector<uint8_t> frame, std::size_t original_size, Sender sender);
    void stop();
    std::size_t queued_packets() const { return queue_.size(); }
    std::size_t queued_bytes() const { return queued_bytes_; }
    std::size_t sent_packets() const { return sent_; }
    std::size_t dropped_packets() const { return dropped_; }
    const TrafficModel& model() const { return model_; }
private:
    struct Pending { std::vector<uint8_t> frame; Sender sender; Clock::time_point due; };
    void arm();
    ShapingConfig config_;
    TrafficModel model_;
    asio::steady_timer timer_;
    std::deque<Pending> queue_;
    std::size_t queued_bytes_ = 0, sent_ = 0, dropped_ = 0;
    bool stopped_ = false;
};

} // namespace pqvpn::traffic
