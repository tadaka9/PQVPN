#include "adaptive_transport.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <stdexcept>
#include <utility>

namespace pqvpn::transport {
namespace {
constexpr std::array<std::uint8_t, 4> kMagic{'P', 'Q', 'T', '1'};
constexpr std::size_t kHeaderBytes = 16;
constexpr std::size_t kMaximumPayload = 65507;

void put_u32(std::vector<std::uint8_t>& out, const std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

std::uint32_t get_u32(const std::span<const std::uint8_t> in, const std::size_t offset) {
    return (static_cast<std::uint32_t>(in[offset]) << 24) |
           (static_cast<std::uint32_t>(in[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(in[offset + 2]) << 8) |
           static_cast<std::uint32_t>(in[offset + 3]);
}
} // namespace

AdaptiveController::AdaptiveController(AdaptiveConfig config, const Clock::time_point now)
    : config_(std::move(config)), last_switch_(now) {
    if (config_.mode == Mode::TcpOnly) {
        lane_ = Lane::Tcp;
        reason_ = "TCP is locked by configuration";
    } else if (config_.mode == Mode::UdpOnly || !config_.enabled) {
        reason_ = config_.enabled ? "UDP is locked by configuration" : "Adaptive transport is disabled";
    }
}

Decision AdaptiveController::select(const Lane lane, std::string reason, const Clock::time_point now) {
    const bool changed = lane != lane_;
    lane_ = lane;
    reason_ = std::move(reason);
    if (changed) last_switch_ = now;
    return {lane_, changed, reason_};
}

Decision AdaptiveController::observe(const PathSample& sample, const Clock::time_point now) {
    if (!config_.enabled || config_.mode == Mode::UdpOnly)
        return select(Lane::Udp, config_.enabled ? "UDP is locked by configuration" : "Adaptive transport is disabled", now);
    if (config_.mode == Mode::TcpOnly)
        return select(Lane::Tcp, "TCP is locked by configuration", now);

    const auto dwell = std::chrono::milliseconds(config_.minimum_dwell_ms);
    if (lane_ == Lane::Udp) {
        udp_failures_ = sample.send_failed ? udp_failures_ + 1 : 0;
        udp_recovery_probes_ = 0;
        if (now - last_switch_ < dwell) return current();
        if (sample.udp_blocked)
            return select(Lane::Tcp, "UDP appears blocked; preserving connectivity over TCP", now);
        if (udp_failures_ >= config_.failure_switch_count)
            return select(Lane::Tcp, "Repeated UDP sends failed", now);
        if (sample.loss_percent >= config_.loss_switch_percent)
            return select(Lane::Tcp, "UDP loss crossed the configured threshold", now);
        if (sample.jitter_ms >= config_.jitter_switch_ms)
            return select(Lane::Tcp, "UDP jitter crossed the configured threshold", now);
        return current();
    }

    const bool healthy_udp_probe = !sample.send_failed && !sample.udp_blocked &&
        sample.loss_percent < config_.loss_switch_percent * 0.5 &&
        sample.jitter_ms < config_.jitter_switch_ms * 0.5;
    udp_recovery_probes_ = healthy_udp_probe ? udp_recovery_probes_ + 1 : 0;
    if (now - last_switch_ >= dwell && udp_recovery_probes_ >= config_.recovery_probe_count) {
        udp_failures_ = 0;
        udp_recovery_probes_ = 0;
        return select(Lane::Udp, "UDP recovered and is again the faster path", now);
    }
    return current();
}

Decision AdaptiveController::current() const { return {lane_, false, reason_}; }

std::vector<std::uint8_t> encode_frame(const Frame& frame) {
    if (frame.payload.size() > kMaximumPayload) throw std::length_error("PQTP payload exceeds the datagram limit");
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderBytes + frame.payload.size());
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    out.push_back(1);
    out.push_back(static_cast<std::uint8_t>(frame.lane));
    out.push_back(0);
    out.push_back(0);
    put_u32(out, frame.sequence);
    put_u32(out, static_cast<std::uint32_t>(frame.payload.size()));
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    return out;
}

std::optional<Frame> decode_frame(const std::span<const std::uint8_t> bytes) {
    if (bytes.size() < kHeaderBytes || !std::equal(kMagic.begin(), kMagic.end(), bytes.begin()) || bytes[4] != 1)
        return std::nullopt;
    if (bytes[5] != static_cast<std::uint8_t>(Lane::Udp) && bytes[5] != static_cast<std::uint8_t>(Lane::Tcp))
        return std::nullopt;
    const auto size = get_u32(bytes, 12);
    if (size > kMaximumPayload || bytes.size() != kHeaderBytes + size) return std::nullopt;
    return Frame{static_cast<Lane>(bytes[5]), get_u32(bytes, 8),
        std::vector<std::uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(kHeaderBytes), bytes.end())};
}

const char* to_string(const Mode mode) noexcept {
    switch (mode) { case Mode::Auto: return "auto"; case Mode::UdpOnly: return "udp"; case Mode::TcpOnly: return "tcp"; }
    return "auto";
}

const char* to_string(const Lane lane) noexcept { return lane == Lane::Udp ? "udp" : "tcp"; }

std::optional<Mode> mode_from_string(const std::string& value) {
    if (value == "auto") return Mode::Auto;
    if (value == "udp") return Mode::UdpOnly;
    if (value == "tcp") return Mode::TcpOnly;
    return std::nullopt;
}

} // namespace pqvpn::transport
