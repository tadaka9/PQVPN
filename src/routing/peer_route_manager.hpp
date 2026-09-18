#ifndef PQVPN_PEER_ROUTE_MANAGER_HPP
#define PQVPN_PEER_ROUTE_MANAGER_HPP

#include <asio.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "routing/route_transaction.hpp"

namespace pqvpn::routing {

/**
 * @brief Keeps tunnel-peer traffic out of a full-tunnel default route.
 *
 * Installing a 0/0 default route on the VPN adapter also captures the node's
 * own UDP transport: peer datagrams would enter the adapter, get re-encrypted
 * by the data path, and loop. The fix is to pin every tunnel peer (and other
 * control-plane destination) to the pre-VPN physical gateway with an explicit
 * /32 host route BEFORE the default route wins, then roll those exclusions
 * back in reverse order on shutdown.
 *
 * Ownership semantics: a route that already existed when we installed it
 * (backend reports already_present) is NOT ours — cleanup never deletes it.
 * Only routes whose install created them are owned and removed. Several peer
 * endpoints may share one address (different ports); the OS route is keyed by
 * address, so removal happens only after the LAST reference to that address
 * disappears. A confirmed removal releases ownership immediately: a later
 * cleanup pass must not delete a route someone else recreated in between.
 *
 * All routing goes through the RouteBackend seam so the logic is testable
 * without touching a real routing table.
 */
class PeerRouteManager {
public:
    /** The pre-VPN egress path that peer traffic must keep using. */
    struct PhysicalGateway {
        asio::ip::address gateway;
        std::uint32_t interface_index = 0; // 0 lets the backend resolve it

        [[nodiscard]] bool valid() const noexcept {
            return !gateway.is_unspecified();
        }
    };

    explicit PeerRouteManager(RouteBackend& backend) : backend_(backend) {}

    /** Records the physical egress path captured before the VPN default route. */
    void set_physical_gateway(PhysicalGateway gateway) { gateway_ = std::move(gateway); }

    [[nodiscard]] bool has_physical_gateway() const noexcept { return gateway_.valid(); }

    /**
     * Installs a /32 host route for `peer` through the physical gateway.
     * Idempotent: re-adding an already-tracked endpoint succeeds again without
     * duplicating bookkeeping, and never starts owning a route that pre-existed
     * (an admin-owned exclusion must survive our shutdown). Fails closed (no
     * backend call) when no physical gateway was captured or the address cannot
     * carry a v4 route.
     */
    OperationResult add_peer(const asio::ip::udp::endpoint& peer);

    /**
     * Drops one reference to the peer's address exclusion. The OS route is
     * removed only when this was the LAST tracked endpoint on that address AND
     * we own it; admin-owned routes are never touched, and a still-referenced
     * shared address keeps its route. Idempotent for unknown endpoints.
     */
    OperationResult remove_peer(const asio::ip::udp::endpoint& peer);

    /**
     * Best-effort removal of every owned exclusion in REVERSE insertion order
     * (most recently added first), so shutdown unwinds the route set the way
     * it was built. Admin-owned routes are skipped entirely; each confirmed
     * removal releases ownership and its references, so a later pass cannot
     * delete a route recreated after we relinquished it. Keeps going past a
     * hard failure (those stay owned for retry); `complete` is false when any
     * removal failed.
     */
    RemovalReport remove_all();

private:
    RouteBackend& backend_;
    PhysicalGateway gateway_{};
    // Logical users of the exclusions, in insertion order. Several endpoints
    // may reference one address (same IP, different ports).
    std::vector<asio::ip::udp::endpoint> peers_;
    // Addresses whose /32 route WE created and still own. An address enters
    // this set only when its install reported already_present == false; it is
    // erased on confirmed removal. Admin-owned addresses never appear here.
    std::map<asio::ip::address, bool> owned_;

    [[nodiscard]] static RouteEntry entry_for(const asio::ip::udp::endpoint& peer,
                                              const PhysicalGateway& gateway);
};

} // namespace pqvpn::routing

#endif
