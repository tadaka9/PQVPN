#include "routing/peer_route_manager.hpp"

#include <algorithm>

namespace pqvpn::routing {

RouteEntry PeerRouteManager::entry_for(const asio::ip::udp::endpoint& peer,
                                       const PhysicalGateway& gateway) {
    return RouteEntry{peer.address(), 32, gateway.gateway, gateway.interface_index};
}

OperationResult PeerRouteManager::add_peer(const asio::ip::udp::endpoint& peer) {
    if (!gateway_.valid()) {
        return {false, false, false, "no physical gateway captured; refusing to add a peer exclusion"};
    }
    if (!peer.address().is_v4() || !gateway_.gateway.is_v4()) {
        return {false, false, false, "peer exclusions are IPv4-only in this backend"};
    }

    // The backend install is idempotent by contract (an existing entry counts
    // as success), so re-adding never duplicates the OS route.
    const auto result = backend_.install(entry_for(peer, gateway_));
    if (!result.ok) return result;

    // Track this endpoint once...
    const bool already_tracked = std::any_of(
        peers_.begin(), peers_.end(),
        [&](const asio::ip::udp::endpoint& existing) { return existing == peer; });
    if (!already_tracked) peers_.push_back(peer);

    // ...and own the address only when THIS install created the route. An
    // already-present route belongs to whoever put it there (an admin, or a
    // previous add of ours that we still own): either way claiming ownership
    // now would make our cleanup destructive.
    if (!result.already_present) {
        owned_[peer.address()] = true;
    }
    return result;
}

OperationResult PeerRouteManager::remove_peer(const asio::ip::udp::endpoint& peer) {
    const auto it = std::find(peers_.begin(), peers_.end(), peer);
    if (it == peers_.end()) {
        // Never tracked: nothing owned to remove. Report idempotent success so
        // callers can treat "already gone" as the desired state.
        return {true, false, true, ""};
    }

    const auto address = peer.address();
    // Drop this reference first; then decide whether anything else still needs
    // the shared OS route.
    peers_.erase(it);

    const bool still_referenced = std::any_of(
        peers_.begin(), peers_.end(),
        [&](const asio::ip::udp::endpoint& existing) { return existing.address() == address; });
    if (still_referenced) {
        // Another tracked endpoint still needs this address's route: leave the
        // shared OS route in place.
        return {true, false, false, ""};
    }

    const auto owned_it = owned_.find(address);
    if (owned_it == owned_.end()) {
        // Last reference, but the route pre-existed us: it is not ours to
        // delete. Report success (desired state).
        return {true, false, true, ""};
    }

    const auto result = backend_.remove(entry_for(peer, gateway_));
    if (!result.ok) {
        // Hard failure: restore the reference so a later remove_all() retries
        // this exact exclusion; ownership stays as well.
        peers_.push_back(peer);
        return result;
    }
    owned_.erase(owned_it); // confirmed removal ends our ownership NOW
    return result;
}

RemovalReport PeerRouteManager::remove_all() {
    RemovalReport report{};
    bool first_failure = true;

    // Unique addresses in reverse insertion order of their endpoints: unwind
    // exclusions the way they were built.
    std::vector<asio::ip::address> ordered;
    for (auto it = peers_.rbegin(); it != peers_.rend(); ++it) {
        const auto address = it->address();
        if (std::find(ordered.begin(), ordered.end(), address) == ordered.end()) {
            ordered.push_back(address);
        }
    }

    for (const auto& address : ordered) {
        // Admin-owned exclusion: never ours to delete. Skip without touching
        // the OS route; its references are released below.
        const auto owned_it = owned_.find(address);
        if (owned_it == owned_.end()) continue;

        const RouteEntry entry{address, 32, gateway_.gateway, gateway_.interface_index};
        const auto result = backend_.remove(entry);
        if (!result.ok) {
            // Hard failure: ownership and references stay for a later retry.
            if (first_failure) report.error = result.error;
            first_failure = false;
            continue; // keep going: shutdown must attempt every owned route
        }
        owned_.erase(owned_it); // confirmed removal ends our ownership NOW
        if (result.not_found) ++report.already_absent;
        else ++report.removed;
    }

    // Release every reference whose route we no longer own: successfully
    // removed addresses, and admin-owned ones we never touched. References to
    // hard-failed (still owned) addresses remain for retry.
    peers_.erase(std::remove_if(peers_.begin(), peers_.end(),
        [&](const asio::ip::udp::endpoint& endpoint) {
            return owned_.find(endpoint.address()) == owned_.end();
        }), peers_.end());

    report.complete = first_failure;
    return report;
}

} // namespace pqvpn::routing
