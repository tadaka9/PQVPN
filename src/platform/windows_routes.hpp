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

// Finds the first IPv4 unicast address on the named adapter (GUID). Returns
// nullopt when the adapter has no IPv4 configured.
std::optional<AdapterRouteInfo> find_adapter_ipv4(const std::string& guid);

// Finds the current IPv4 default route (destination 0.0.0.0, zero mask): its
// next hop and owning interface — i.e., where peer traffic egresses BEFORE a
// VPN adapter takes over. Entries on excluded_ifindex are skipped when it is
// non-zero (e.g., the TAP adapter's own default route). Returns nullopt when
// no usable default route exists.
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
