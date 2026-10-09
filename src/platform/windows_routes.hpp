#pragma once

#ifdef _WIN32

#include <asio.hpp>

#include <cstdint>
#include <optional>
#include <string>

#include "routing/route_transaction.hpp"

namespace pqvpn::platform {

/**
 * @brief IPv4 address and interface index of a TAP adapter.
 */
struct AdapterRouteInfo {
    asio::ip::address ipv4;
    std::uint32_t interface_index = 0;
};

// Finds the first IPv4 unicast address on the adapter GUID or friendly name. Returns
// nullopt when the adapter has no IPv4 configured.
std::optional<AdapterRouteInfo> find_adapter_ipv4(const std::string& guid);

// Finds the first non-link-local IPv6 unicast address on the adapter GUID or
// friendly name. Returns nullopt when the adapter has no usable IPv6.
// The VPN uses this to decide whether it can carry IPv6 in the tunnel;
// without one it must still blackhole the IPv6 default to avoid a leak.
std::optional<AdapterRouteInfo> find_adapter_ipv6(const std::string& guid);

// Finds the IPv6 default route (::/0) peer traffic should keep using BEFORE a
// VPN adapter takes over. Returns nullopt when no usable IPv6 default exists.
// Unlike the IPv4 variant this is not IPv6-leak-critical for the node itself,
// but a full-tunnel IPv6 default on the adapter would otherwise loop IPv6
// peer transport for the same reason as IPv4.
std::optional<AdapterRouteInfo> find_default_route_v6(std::uint32_t excluded_ifindex = 0);

// Finds the IPv4 default route peer traffic should keep using BEFORE a VPN
// adapter takes over: its next hop and owning interface. Selection prefers
// the route the kernel itself resolves (GetBestRoute, effective cost
// including interface metrics) so multi-homed hosts do not pin peers to an
// inactive or lower-priority gateway; if that is unavailable it scans the
// forward table for active defaults with the lowest primary metric.
// Entries on excluded_ifindex are skipped when it is non-zero (e.g., the TAP
// adapter's own default route). Returns nullopt when no usable default exists.
std::optional<AdapterRouteInfo> find_default_route(std::uint32_t excluded_ifindex = 0);

/**
 * @brief Windows routing-table backend over iphlpapi forward entries.
 *
 * Install is idempotent (an existing entry counts as success) and remove is
 * idempotent (a missing entry counts as success), which is what the
 * transactional rollback and shutdown cleanup rely on.
 */
class WindowsRouteBackend : public routing::RouteBackend {
public:
    routing::OperationResult install(const routing::RouteEntry& entry) override;
    routing::OperationResult remove(const routing::RouteEntry& entry) override;
};

} // namespace pqvpn::platform

#endif
