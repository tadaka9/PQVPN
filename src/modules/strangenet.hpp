#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace pqvpn::strangenet {

inline constexpr std::size_t kMaxRoomBytes = 64;
inline constexpr std::size_t kMaxSenderBytes = 64;
inline constexpr std::size_t kMaxMessageBytes = 2048;
inline constexpr std::size_t kMaxReplayStreams = 4096;
inline constexpr std::size_t kMaxFloodStreams = 4096;
inline constexpr std::size_t kMaxFloodRooms = 256;
inline constexpr std::size_t kMaxBroadcastRecipients = 512;

enum class Kind : std::uint8_t {
    Text = 1,
    Acknowledgement = 2,
    Sticker = 3,
    Reaction = 4,
};

struct Message {
    std::string room;
    std::string sender;
    std::uint64_t sequence = 0;
    std::uint64_t timestamp_ms = 0;
    std::string text;
    Kind kind = Kind::Text;
    std::uint64_t reply_to = 0;
};

std::optional<std::vector<std::uint8_t>> encode(const Message& message);
std::optional<Message> decode(std::span<const std::uint8_t> frame);

// Per-room, per-sender monotonic replay guard. Transport authentication still
// comes from the PQVPN session; this guard prevents duplicated chat delivery.
class ReplayGuard {
public:
    bool accept(const Message& message);
    void leave_room(const std::string& room);

private:
    struct ReplayState {
        std::uint64_t highest = 0;
        std::uint64_t bitmap = 0;
    };
    std::unordered_map<std::string, ReplayState> streams_;
};

struct FloodDecision {
    bool allowed = false;
    std::uint64_t retry_after_ms = 0;
};

// Bounds authenticated chat traffic before it reaches UI or receipt fanout.
// A per-sender bucket prevents one identity from dominating a room, while a
// room bucket keeps aggregate work bounded when the audience is very large.
// State has hard caps and expires when idle, so untrusted room/sender labels
// cannot grow memory without limit.
class FloodGuard {
public:
    FloodDecision accept(const Message& message, std::uint64_t now_ms);

private:
    struct Bucket {
        double tokens = 0.0;
        std::uint64_t updated_ms = 0;
        std::uint64_t last_seen_ms = 0;
    };
    std::unordered_map<std::string, Bucket> senders_;
    std::unordered_map<std::string, Bucket> rooms_;
};

} // namespace pqvpn::strangenet
