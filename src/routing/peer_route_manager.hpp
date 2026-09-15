#ifndef PQVPN_PEER_ROUTE_MANAGER_HPP
#define PQVPN_PEER_ROUTE_MANAGER_HPP

#include <asio.hpp>

#include <cstdint>
#include <functional>
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
     * Idempotent: re-adding an already-excluded peer succeeds again without
     * duplicating bookkeeping. Fails closed (no backend call) when no
     * physical gateway was captured or the address cannot carry a v4 route.
     */
    OperationResult add_peer(const asio::ip::udp::endpoint& peer);

    /** Removes one previously added exclusion; idempotent like the backend. */
    OperationResult remove_peer(const asio::ip::udp::endpoint& peer);

    /**
     * Best-effort removal of every owned exclusion in REVERSE insertion order
     * (most recently added first), so shutdown unwinds the route set the way
     * it was built. Keeps going past a hard failure; `complete` is false when
     * any removal failed.
     */
    RemovalReport remove_all() const;

private:
    RouteBackend& backend_;
    PhysicalGateway gateway_{};
    // Insertion order of owned exclusions, for reverse-order rollback.
    std::vector<asio::ip::udp::endpoint> peers_;
};

} // namespace pqvpn::routing

#endif
