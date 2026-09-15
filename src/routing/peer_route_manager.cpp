#include "routing/peer_route_manager.hpp"

#include <algorithm>

namespace pqvpn::routing {

OperationResult PeerRouteManager::add_peer(const asio::ip::udp::endpoint& peer) {
    if (!gateway_.valid()) {
        return {false, false, false, "no physical gateway captured; refusing to add a peer exclusion"};
    }
    if (!peer.address().is_v4() || !gateway_.gateway.is_v4()) {
        return {false, false, false, "peer exclusions are IPv4-only in this backend"};
    }

    const RouteEntry entry{peer.address(), 32, gateway_.gateway, gateway_.interface_index};
    // The backend install is idempotent by contract (an existing entry counts
    // as success), so re-adding never duplicates the OS route.
    const auto result = backend_.install(entry);
    if (!result.ok) return result;

    const bool already_tracked = std::any_of(
        peers_.begin(), peers_.end(),
        [&](const asio::ip::udp::endpoint& existing) { return existing == peer; });
    if (!already_tracked) peers_.push_back(peer);
    return result;
}

OperationResult PeerRouteManager::remove_peer(const asio::ip::udp::endpoint& peer) {
    const auto it = std::find(peers_.begin(), peers_.end(), peer);
    if (it == peers_.end()) {
        // Never tracked: nothing owned to remove. Report idempotent success so
        // callers can treat "already gone" as the desired state.
        return {true, false, true, ""};
    }

    const RouteEntry entry{peer.address(), 32, gateway_.gateway, gateway_.interface_index};
    const auto result = backend_.remove(entry);
    if (result.ok) {
        peers_.erase(it);
    }
    // A hard failure keeps the peer tracked so remove_all() retries it.
    return result;
}

RemovalReport PeerRouteManager::remove_all() const {
    RemovalReport report{};
    bool first_failure = true;
    // Reverse insertion order: unwind exclusions the way they were built, so a
    // partially rolled-back state never leaves newer routes shadowing older ones.
    for (auto it = peers_.rbegin(); it != peers_.rend(); ++it) {
        const RouteEntry entry{(*it).address(), 32, gateway_.gateway, gateway_.interface_index};
        const auto result = backend_.remove(entry);
        if (!result.ok) {
            if (first_failure) report.error = result.error;
            first_failure = false;
            continue; // keep going: shutdown must attempt every owned route
        }
        if (result.not_found) ++report.already_absent;
        else ++report.removed;
    }
    report.complete = first_failure;
    return report;
}

} // namespace pqvpn::routing
