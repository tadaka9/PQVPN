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
// Protocol/type constants for MIB_IPFORWARDROW; values are stable.
// NETMGMT is 3 on both toolchains (MS nldef.h RouteProtocolNetMgmt=3;
// MinGW iprtrmib.h MIB_IPPROTO_NETMGMT=3).
#ifndef MIB_IPPROTO_NETMGMT
#define MIB_IPPROTO_NETMGMT 3L
#endif
#ifndef GATEWAY_STATIC
#define GATEWAY_STATIC 4L
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

    // A default route is destination 0.0.0.0 with a zero mask (prefix length
    // 0), matching every IPv4 destination; netmask_nbo(0) yields that mask.
    MIB_IPFORWARDROW row{};
    row.dwForwardDest = entry.prefix.to_v4().to_uint();
    row.dwForwardMask = netmask_nbo(entry.prefix_length);
    row.dwForwardNextHop = entry.gateway.to_v4().to_uint();
    row.dwForwardIfIndex = interface_index;
    // CreateIpForwardEntry fails with ERROR_INVALID_PARAMETER (87) unless the
    // protocol is MIB_IPPROTO_NETMGMT — MSDN: "must be set to
    // MIB_IPPROTO_NETMGMT otherwise CreateIpForwardEntry will fail". Leaving it
    // at zero made every install fail on real Windows.
    row.dwForwardProto = MIB_IPPROTO_NETMGMT;
    // dwForwardType is not matched by DeleteIpForwardEntry and not validated
    // by CreateIpForwardEntry (MSDN), but a static-gateway value keeps `route
    // print` output sane.
    row.dwForwardType = GATEWAY_STATIC;

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

// Interface oper status when the table is available (SNMP: 1=up). Rows on
// interfaces KNOWN to be down are unusable; an unknown interface is not
// excluded on status alone.
bool interface_known_down(const std::uint32_t ifindex) {
    ULONG size = 0;
    if (GetIfTable(nullptr, &size, FALSE) != ERROR_BUFFER_OVERFLOW || size == 0) return false;
    std::vector<uint8_t> storage(size);
    auto* table = reinterpret_cast<MIB_IFTABLE*>(storage.data());
    if (GetIfTable(table, &size, FALSE) != NO_ERROR) return false;
    for (ULONG index = 0; index < table->dwNumEntries; ++index) {
        if (table->table[index].dwIndex == ifindex) {
            return table->table[index].dwOperStatus != 1;
        }
    }
    return false;
}

std::optional<AdapterRouteInfo> find_default_route(const std::uint32_t excluded_ifindex) {
    // This toolchain's iphlpapi.h declares the legacy three-argument forms
    // (with bOrder) and lowercase `table` members; both are stable.

    // Preferred: ask the kernel which route it would actually use for an
    // arbitrary destination. GetBestRoute resolves effective cost including
    // interface metrics, so a multi-homed host picks the gateway Windows
    // itself prefers — not merely the first row in the table (a disconnected
    // adapter's default must not win over the active one).
    MIB_IPFORWARDROW best{};
    if (GetBestRoute(0 /*any destination*/, 0 /*local source*/, &best) == NO_ERROR &&
        best.dwForwardDest == 0 && best.dwForwardMask == 0 &&
        !(excluded_ifindex != 0 && best.dwForwardIfIndex == excluded_ifindex)) {
        AdapterRouteInfo info{};
        // dwForwardNextHop is network byte order, as address_v4 expects.
        info.ipv4 = asio::ip::address(asio::ip::address_v4(best.dwForwardNextHop));
        info.interface_index = best.dwForwardIfIndex;
        return info;
    }

    // Fallback: scan the forward table for default routes (destination 0.0.0.0
    // with a zero mask), skipping the excluded interface and interfaces known
    // to be down, and pick the lowest primary metric; ties keep first-seen
    // order so the choice stays deterministic.
    ULONG size = 0;
    if (GetIpForwardTable(nullptr, &size, FALSE) != ERROR_BUFFER_OVERFLOW || size == 0) {
        return std::nullopt;
    }
    std::vector<uint8_t> storage(size);
    auto* table = reinterpret_cast<MIB_IPFORWARDTABLE*>(storage.data());
    if (GetIpForwardTable(table, &size, FALSE) != NO_ERROR) {
        return std::nullopt;
    }

    const MIB_IPFORWARDROW* best_row = nullptr;
    DWORD best_metric = 0xFFFFFFFF;
    for (ULONG index = 0; index < table->dwNumEntries; ++index) {
        const auto& row = table->table[index];
        if (excluded_ifindex != 0 && row.dwForwardIfIndex == excluded_ifindex) continue;
        if (row.dwForwardDest != 0 || row.dwForwardMask != 0) continue;
        if (interface_known_down(row.dwForwardIfIndex)) continue;
        if (!best_row || row.dwForwardMetric1 < best_metric) {
            best_row = &row;
            best_metric = row.dwForwardMetric1;
        }
    }
    if (!best_row) return std::nullopt;

    AdapterRouteInfo info{};
    // dwForwardNextHop is network byte order, as address_v4 expects.
    info.ipv4 = asio::ip::address(asio::ip::address_v4(best_row->dwForwardNextHop));
    info.interface_index = best_row->dwForwardIfIndex;
    return info;
}

routing::OperationResult WindowsRouteBackend::install(const routing::RouteEntry& entry) {
    return apply(true, entry);
}

routing::OperationResult WindowsRouteBackend::remove(const routing::RouteEntry& entry) {
    return apply(false, entry);
}

} // namespace pqvpn::platform

#endif
