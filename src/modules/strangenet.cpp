#include "strangenet.hpp"

#include <algorithm>
#include <array>
#include <cmath>

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
    if (std::any_of(value.begin(), value.end(), [](const unsigned char character) {
        return character == 0 || character < 0x09;
    })) return false;
    const auto* data = reinterpret_cast<const unsigned char*>(value.data());
    for (std::size_t i = 0; i < value.size();) {
        const auto first = data[i];
        if (first <= 0x7f) { ++i; continue; }
        std::size_t count = 0; std::uint32_t codepoint = 0;
        if (first >= 0xc2 && first <= 0xdf) { count = 2; codepoint = first & 0x1f; }
        else if (first >= 0xe0 && first <= 0xef) { count = 3; codepoint = first & 0x0f; }
        else if (first >= 0xf0 && first <= 0xf4) { count = 4; codepoint = first & 0x07; }
        else return false;
        if (i + count > value.size()) return false;
        for (std::size_t offset = 1; offset < count; ++offset) {
            if ((data[i + offset] & 0xc0) != 0x80) return false;
            codepoint = (codepoint << 6) | (data[i + offset] & 0x3f);
        }
        if ((count == 3 && codepoint < 0x800) || (count == 4 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff) return false;
        i += count;
    }
    return true;
}
} // namespace

std::optional<std::vector<std::uint8_t>> encode(const Message& message) {
    const bool ack = message.kind == Kind::Acknowledgement;
    const bool reaction = message.kind == Kind::Reaction;
    const bool voice = message.kind == Kind::Voice;
    const bool direct = message.kind == Kind::DirectText;
    const bool profile = message.kind == Kind::Profile;
    const bool world = message.kind == Kind::World;
    if ((message.kind != Kind::Text && !ack && message.kind != Kind::Sticker && !reaction && !voice && !direct && !profile && !world) ||
        message.room.empty() || message.room.size() > kMaxRoomBytes || message.sender.empty() ||
        message.sender.size() > kMaxSenderBytes || (!ack && message.text.empty()) ||
        (ack && (!message.text.empty() || message.reply_to == 0)) ||
        (reaction && message.reply_to == 0) ||
        (message.kind != Kind::Text && !ack && !reaction && message.reply_to != 0) ||
        message.text.size() > kMaxMessageBytes || message.sequence == 0 ||
        !valid_text(message.room) || !valid_text(message.sender) || !valid_text(message.text)) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve(36 + message.room.size() + message.sender.size() + message.text.size());
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    out.push_back(voice ? 3 : 2);
    out.push_back(static_cast<std::uint8_t>(message.kind));
    put_u16(out, message.room.size());
    put_u16(out, message.sender.size());
    put_u16(out, message.text.size());
    put_u64(out, message.sequence);
    put_u64(out, message.timestamp_ms);
    put_u64(out, message.reply_to);
    out.insert(out.end(), message.room.begin(), message.room.end());
    out.insert(out.end(), message.sender.begin(), message.sender.end());
    out.insert(out.end(), message.text.begin(), message.text.end());
    return out;
}

std::optional<Message> decode(const std::span<const std::uint8_t> frame) {
    if (frame.size() < 27 || !std::equal(kMagic.begin(), kMagic.end(), frame.begin()) ||
        (frame[4] != 1 && frame[4] != 2 && frame[4] != 3)) return std::nullopt;
    const bool legacy = frame[4] == 1;
    const std::size_t header = legacy ? 27 : 36;
    if (frame.size() < header) return std::nullopt;
    const auto kind = legacy ? Kind::Text : static_cast<Kind>(frame[5]);
    const auto base = legacy ? std::size_t{5} : std::size_t{6};
    const auto room_size = get_u16(frame, base), sender_size = get_u16(frame, base + 2), text_size = get_u16(frame, base + 4);
    if (room_size == 0 || room_size > kMaxRoomBytes || sender_size == 0 || sender_size > kMaxSenderBytes ||
        text_size > kMaxMessageBytes || frame.size() != header + room_size + sender_size + text_size) return std::nullopt;
    Message message;
    message.kind = kind;
    message.sequence = get_u64(frame, base + 6);
    message.timestamp_ms = get_u64(frame, base + 14);
    if (!legacy) message.reply_to = get_u64(frame, base + 22);
    if (message.sequence == 0) return std::nullopt;
    std::size_t cursor = header;
    message.room.assign(reinterpret_cast<const char*>(frame.data() + cursor), room_size); cursor += room_size;
    message.sender.assign(reinterpret_cast<const char*>(frame.data() + cursor), sender_size); cursor += sender_size;
    message.text.assign(reinterpret_cast<const char*>(frame.data() + cursor), text_size);
    const bool ack = message.kind == Kind::Acknowledgement;
    const bool reaction = message.kind == Kind::Reaction;
    const bool voice = message.kind == Kind::Voice;
    const bool direct = message.kind == Kind::DirectText;
    const bool profile = message.kind == Kind::Profile;
    const bool world = message.kind == Kind::World;
    if ((message.kind != Kind::Text && !ack && message.kind != Kind::Sticker && !reaction && !voice && !direct && !profile && !world) ||
        (voice && frame[4] != 3) ||
        (ack && (!message.text.empty() || message.reply_to == 0)) ||
        (!ack && message.text.empty()) || (reaction && message.reply_to == 0) ||
        (message.kind != Kind::Text && !ack && !reaction && message.reply_to != 0) ||
        !valid_text(message.room) || !valid_text(message.sender) || !valid_text(message.text)) return std::nullopt;
    return message;
}

bool ReplayGuard::accept(const Message& message) {
    const auto key = message.room + '\0' + message.sender;
    auto found = streams_.find(key);
    if (found == streams_.end()) {
        if (streams_.size() >= kMaxReplayStreams) return false;
        found = streams_.emplace(key, ReplayState{}).first;
    }
    auto& state = found->second;
    if (message.sequence > state.highest) {
        const auto advance = message.sequence - state.highest;
        state.bitmap = advance >= 64 ? 1 : (state.bitmap << advance) | 1;
        state.highest = message.sequence;
        return true;
    }
    const auto distance = state.highest - message.sequence;
    if (distance >= 64) return false;
    const std::uint64_t bit = std::uint64_t{1} << distance;
    if ((state.bitmap & bit) != 0) return false;
    state.bitmap |= bit;
    return true;
}

void ReplayGuard::leave_room(const std::string& room) {
    const auto prefix = room + '\0';
    for (auto it = streams_.begin(); it != streams_.end();) {
        if (it->first.starts_with(prefix)) it = streams_.erase(it); else ++it;
    }
}

FloodDecision FloodGuard::accept(const Message& message, const std::uint64_t now_ms) {
    constexpr double sender_rate = 2.0;
    constexpr double sender_burst = 8.0;
    constexpr double room_rate = 32.0;
    constexpr double room_burst = 128.0;
    constexpr std::uint64_t idle_expiry_ms = 5 * 60 * 1000;

    const double payload_cost = 1.0 +
        static_cast<double>(message.text.empty() ? 0 : message.text.size() - 1) / 512.0;
    const double cost = message.kind == Kind::Acknowledgement ? 0.25
        : (message.kind == Kind::Reaction ? 0.5
        : (message.kind == Kind::Voice ? 0.02
        : (message.kind == Kind::World ? 0.25 : payload_cost)));
    const auto& sender_key = message.sender;

    auto expire_idle = [now_ms](auto& buckets, const std::uint64_t expiry) {
        for (auto it = buckets.begin(); it != buckets.end();) {
            if (now_ms >= it->second.last_seen_ms && now_ms - it->second.last_seen_ms >= expiry)
                it = buckets.erase(it);
            else
                ++it;
        }
    };
    if (!senders_.contains(sender_key) && senders_.size() >= kMaxFloodStreams)
        expire_idle(senders_, idle_expiry_ms);
    if (!rooms_.contains(message.room) && rooms_.size() >= kMaxFloodRooms)
        expire_idle(rooms_, idle_expiry_ms);
    if ((!senders_.contains(sender_key) && senders_.size() >= kMaxFloodStreams) ||
        (!rooms_.contains(message.room) && rooms_.size() >= kMaxFloodRooms))
        return {false, 1000};

    auto prepare = [now_ms](Bucket& bucket, const double rate, const double burst) {
        if (bucket.updated_ms == 0) {
            bucket.tokens = burst;
            bucket.updated_ms = now_ms;
        } else if (now_ms > bucket.updated_ms) {
            bucket.tokens = std::min(burst, bucket.tokens +
                static_cast<double>(now_ms - bucket.updated_ms) * rate / 1000.0);
            bucket.updated_ms = now_ms;
        }
        bucket.last_seen_ms = now_ms;
    };
    auto& sender = senders_[sender_key];
    auto& room = rooms_[message.room];
    prepare(sender, sender_rate, sender_burst);
    prepare(room, room_rate, room_burst);

    if (sender.tokens < cost || room.tokens < cost) {
        const double sender_wait = std::max(0.0, cost - sender.tokens) / sender_rate;
        const double room_wait = std::max(0.0, cost - room.tokens) / room_rate;
        return {false, static_cast<std::uint64_t>(std::ceil(std::max(sender_wait, room_wait) * 1000.0))};
    }
    sender.tokens -= cost;
    room.tokens -= cost;
    return {true, 0};
}

} // namespace pqvpn::strangenet
