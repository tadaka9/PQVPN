#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pqvpn::transport {

enum class Mode { Auto, UdpOnly, TcpOnly };
enum class Lane : std::uint8_t { Udp = 1, Tcp = 2 };

struct AdaptiveConfig {
    bool enabled = false;
    Mode mode = Mode::Auto;
    double loss_switch_percent = 12.0;
    double jitter_switch_ms = 45.0;
    unsigned failure_switch_count = 3;
    unsigned recovery_probe_count = 4;
    unsigned minimum_dwell_ms = 5000;
};

struct PathSample {
    double loss_percent = 0.0;
    double jitter_ms = 0.0;
    double rtt_ms = 0.0;
    bool send_failed = false;
    bool udp_blocked = false;
};

struct Decision {
    Lane lane = Lane::Udp;
    bool changed = false;
    std::string reason = "UDP is the preferred low-latency path";
};

class AdaptiveController {
public:
    using Clock = std::chrono::steady_clock;

    explicit AdaptiveController(AdaptiveConfig config = {}, Clock::time_point now = Clock::now());
    Decision observe(const PathSample& sample, Clock::time_point now = Clock::now());
    [[nodiscard]] Decision current() const;
    [[nodiscard]] const AdaptiveConfig& config() const noexcept { return config_; }

private:
    Decision select(Lane lane, std::string reason, Clock::time_point now);

    AdaptiveConfig config_;
    Lane lane_ = Lane::Udp;
    std::string reason_ = "UDP is the preferred low-latency path";
    unsigned udp_failures_ = 0;
    unsigned udp_recovery_probes_ = 0;
    Clock::time_point last_switch_;
};

struct Frame {
    Lane lane = Lane::Udp;
    std::uint32_t sequence = 0;
    std::vector<std::uint8_t> payload;
};

// PQTP/1 preserves the already-authenticated PQVPN datagram as an opaque
// payload. TCP uses the length field for message boundaries; UDP uses the
// same envelope so switching paths never changes the cryptographic frame.
std::vector<std::uint8_t> encode_frame(const Frame& frame);
std::optional<Frame> decode_frame(std::span<const std::uint8_t> bytes);

const char* to_string(Mode mode) noexcept;
const char* to_string(Lane lane) noexcept;
std::optional<Mode> mode_from_string(const std::string& value);

} // namespace pqvpn::transport
