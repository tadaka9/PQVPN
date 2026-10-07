#include "strangenet.hpp"

#include <algorithm>
#include <array>

namespace pqvpn::strangenet {
namespace {
constexpr std::array<std::uint8_t, 4> kMagic{'S', 'T', 'R', 'N'};

void put_u16(std::vector<std::uint8_t>& out, const std::size_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}
void put_u64(std::vector<std::uint8_t>& out, const std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(value >> shift));
}
std::uint16_t get_u16(const std::span<const std::uint8_t> in, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[offset]) << 8) | in[offset + 1]);
}
std::uint64_t get_u64(const std::span<const std::uint8_t> in, const std::size_t offset) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) value = (value << 8) | in[offset + index];
    return value;
}
bool valid_text(const std::string& value) {
    for (const unsigned char character : value) if (character == 0 || character < 0x09) return false;
    return true;
}
} // namespace

std::optional<std::vector<std::uint8_t>> encode(const Message& message) {
    if (message.room.empty() || message.room.size() > kMaxRoomBytes || message.sender.empty() ||
        message.sender.size() > kMaxSenderBytes || message.text.empty() ||
        message.text.size() > kMaxMessageBytes || message.sequence == 0 ||
        !valid_text(message.room) || !valid_text(message.sender) || !valid_text(message.text)) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve(27 + message.room.size() + message.sender.size() + message.text.size());
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    out.push_back(1);
    put_u16(out, message.room.size());
    put_u16(out, message.sender.size());
    put_u16(out, message.text.size());
    put_u64(out, message.sequence);
    put_u64(out, message.timestamp_ms);
    out.insert(out.end(), message.room.begin(), message.room.end());
    out.insert(out.end(), message.sender.begin(), message.sender.end());
    out.insert(out.end(), message.text.begin(), message.text.end());
    return out;
}

std::optional<Message> decode(const std::span<const std::uint8_t> frame) {
    constexpr std::size_t header = 27;
    if (frame.size() < header || !std::equal(kMagic.begin(), kMagic.end(), frame.begin()) || frame[4] != 1) return std::nullopt;
    const auto room_size = get_u16(frame, 5), sender_size = get_u16(frame, 7), text_size = get_u16(frame, 9);
    if (room_size == 0 || room_size > kMaxRoomBytes || sender_size == 0 || sender_size > kMaxSenderBytes ||
        text_size == 0 || text_size > kMaxMessageBytes || frame.size() != header + room_size + sender_size + text_size) return std::nullopt;
    Message message;
    message.sequence = get_u64(frame, 11);
    message.timestamp_ms = get_u64(frame, 19);
    if (message.sequence == 0) return std::nullopt;
    std::size_t cursor = header;
    message.room.assign(reinterpret_cast<const char*>(frame.data() + cursor), room_size); cursor += room_size;
    message.sender.assign(reinterpret_cast<const char*>(frame.data() + cursor), sender_size); cursor += sender_size;
    message.text.assign(reinterpret_cast<const char*>(frame.data() + cursor), text_size);
    if (!valid_text(message.room) || !valid_text(message.sender) || !valid_text(message.text)) return std::nullopt;
    return message;
}

bool ReplayGuard::accept(const Message& message) {
    const auto key = message.room + '\0' + message.sender;
    auto& highest = highest_sequence_[key];
    if (message.sequence <= highest) return false;
    highest = message.sequence;
    return true;
}

void ReplayGuard::leave_room(const std::string& room) {
    const auto prefix = room + '\0';
    for (auto it = highest_sequence_.begin(); it != highest_sequence_.end();) {
        if (it->first.starts_with(prefix)) it = highest_sequence_.erase(it); else ++it;
    }
}

} // namespace pqvpn::strangenet
