#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <vector>

namespace pqvpn::group_chat {

inline constexpr std::size_t kMinParticipants = 3;
inline constexpr std::size_t kMaxParticipants = 64;

inline bool valid_peer_id(const std::string& value) {
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

// A group is an explicit, immutable recipient set for one joined room.  The
// local identity counts as a participant, so at least two remote identities
// are required.  Sorting makes the same group canonical on every member.
inline bool canonicalize_members(
    const std::string& local_peer,
    std::vector<std::string>& remote_peers) {
    if (!valid_peer_id(local_peer) || remote_peers.size() + 1 < kMinParticipants ||
        remote_peers.size() + 1 > kMaxParticipants) return false;
    std::transform(remote_peers.begin(), remote_peers.end(), remote_peers.begin(),
        [](std::string value) {
            std::transform(value.begin(), value.end(), value.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        });
    if (std::any_of(remote_peers.begin(), remote_peers.end(), [&](const auto& peer) {
        return !valid_peer_id(peer) || peer == local_peer;
    })) return false;
    std::sort(remote_peers.begin(), remote_peers.end());
    return std::adjacent_find(remote_peers.begin(), remote_peers.end()) == remote_peers.end();
}

} // namespace pqvpn::group_chat
