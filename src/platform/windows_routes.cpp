#ifdef _WIN32

#include "windows_routes.hpp"

#include <string>
#include <vector>

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

// This toolchain's iphlpapi header does not define the forward-entry status
// codes; their values are stable Windows error codes.
#ifndef ERROR_ENTRY_ALREADY_EXISTS
#define ERROR_ENTRY_ALREADY_EXISTS 4294L
#endif
#ifndef ERROR_ENTRY_NOT_FOUND
#define ERROR_ENTRY_NOT_FOUND 4295L
#endif

namespace pqvpn::platform {
namespace {

std::string win_error(const std::string& operation, const DWORD code) {
    return operation + " failed (Windows error " + std::to_string(code) + ")";
}

asio::ip::address unicast_ipv4(const IP_ADAPTER_UNICAST_ADDRESS* unicast) {
    if (!unicast || !unicast->Address.lpSockaddr) return {};
    const auto* sock = unicast->Address.lpSockaddr;
    if (sock->sa_family != AF_INET) return {};
    // sin_addr is already in network byte order, as address_v4 expects.
    const auto* sin = reinterpret_cast<const sockaddr_in*>(sock);
    return asio::ip::address(asio::ip::address_v4(sin->sin_addr.S_un.S_addr));
}

// Resolves the interface that owns `gateway` when a route entry does not name
// one. Returns 0 when no local interface carries that address.
std::uint32_t resolve_interface(const asio::ip::address& gateway) {
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr, nullptr, &size)
            != ERROR_BUFFER_OVERFLOW || size == 0) {
        return 0;
    }
    std::vector<uint8_t> storage(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr,
            adapters, &size) != NO_ERROR) {
        return 0;
    }
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            if (unicast_ipv4(unicast) == gateway) return adapter->IfIndex;
        }
    }
    return 0;
}

// Subnet mask for a v4 prefix length, in network byte order.
std::uint32_t netmask_nbo(const std::uint8_t prefix_length) {
    const auto host_bits = 32u - static_cast<unsigned>(prefix_length);
    const auto mask_host_order = (host_bits >= 32u) ? 0u : (~0u << host_bits);
    return htonl(mask_host_order);
}

routing::OperationResult apply(const bool install, const routing::RouteEntry& entry) {
    if (!entry.prefix.is_v4() || !entry.gateway.is_v4() || entry.prefix_length > 32) {
        return {false, false, false, "this backend installs IPv4 routes only"};
    }

    std::uint32_t interface_index = entry.interface_index;
    if (interface_index == 0) interface_index = resolve_interface(entry.gateway);
    if (interface_index == 0) {
        return {false, false, false, "gateway is not on any local interface"};
    }

    // Rows use the Windows default-route convention: destination 0.0.0.0 with
    // an all-ones mask and the adapter address as next hop (the shape
    // `route add` produces).
    MIB_IPFORWARDROW row{};
    row.dwForwardDest = entry.prefix.to_v4().to_uint();
    row.dwForwardMask = netmask_nbo(entry.prefix_length);
    row.dwForwardNextHop = entry.gateway.to_v4().to_uint();
    row.dwForwardIfIndex = interface_index;

    const auto status = install ? CreateIpForwardEntry(&row) : DeleteIpForwardEntry(&row);
    if (status == NO_ERROR) return {true};
    if (install && status == ERROR_ENTRY_ALREADY_EXISTS) {
        return {true, true, false, ""}; // already in place: desired state reached
    }
    if (!install && status == ERROR_ENTRY_NOT_FOUND) {
        return {true, false, true, ""}; // nothing to remove: idempotent success
    }
    const auto operation = install ? "CreateIpForwardEntry" : "DeleteIpForwardEntry";
    return {false, false, false, win_error(operation, status)};
}

} // namespace

std::optional<AdapterRouteInfo> find_adapter_ipv4(const std::string& guid) {
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr, nullptr, &size)
            != ERROR_BUFFER_OVERFLOW || size == 0) {
        return std::nullopt;
    }
    std::vector<uint8_t> storage(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr,
            adapters, &size) != NO_ERROR) {
        return std::nullopt;
    }

    // This toolchain reports AdapterName as an ANSI string.
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        if (!adapter->AdapterName || std::string(adapter->AdapterName) != guid) continue;
        for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            const auto ipv4 = unicast_ipv4(unicast);
            if (ipv4.is_v4()) return AdapterRouteInfo{ipv4, adapter->IfIndex};
        }
    }
    return std::nullopt;
}

routing::OperationResult WindowsRouteBackend::install(const routing::RouteEntry& entry) {
    return apply(true, entry);
}

routing::OperationResult WindowsRouteBackend::remove(const routing::RouteEntry& entry) {
    return apply(false, entry);
}

} // namespace pqvpn::platform

#endif
