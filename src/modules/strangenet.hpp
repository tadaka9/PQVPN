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

struct Message {
    std::string room;
    std::string sender;
    std::uint64_t sequence = 0;
    std::uint64_t timestamp_ms = 0;
    std::string text;
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
    std::unordered_map<std::string, std::uint64_t> highest_sequence_;
};

} // namespace pqvpn::strangenet
