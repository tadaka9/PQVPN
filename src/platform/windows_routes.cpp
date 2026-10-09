#ifdef _WIN32

#include "windows_routes.hpp"

#include <string>
#include <vector>

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <ws2ipdef.h>

#include <algorithm>
#include <cstring>
#include <iterator>

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

asio::ip::address unicast_ipv6(const IP_ADAPTER_UNICAST_ADDRESS* unicast) {
    if (!unicast || !unicast->Address.lpSockaddr) return {};
    const auto* sock = unicast->Address.lpSockaddr;
    if (sock->sa_family != AF_INET6) return {};
    const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sock);
    asio::ip::address_v6::bytes_type bytes{};
    std::copy(std::begin(sin6->sin6_addr.s6_addr), std::end(sin6->sin6_addr.s6_addr),
              bytes.begin());
    return asio::ip::address(asio::ip::address_v6(bytes, sin6->sin6_scope_id));
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
            if (gateway.is_v6() ? (unicast_ipv6(unicast) == gateway)
                                : (unicast_ipv4(unicast) == gateway)) {
                return adapter->IfIndex;
            }
        }
    }
    return 0;
}

// Installs or removes an IPv6 forward entry through the iphlpapi v2 API
// (MIB_IPFORWARD_ROW2). Supports both routing through a real next hop and a
// blackhole entry (::/0 to the loopback ::1), which is how the VPN keeps the
// host's global IPv6 address from leaking while it only carries IPv4.
routing::OperationResult apply_v6(const bool install, const routing::RouteEntry& entry) {
    std::uint32_t interface_index = entry.interface_index;
    if (interface_index == 0) interface_index = resolve_interface(entry.gateway);
    if (interface_index == 0) {
        return {false, false, false, "IPv6 gateway is not on any local interface"};
    }

    MIB_IPFORWARD_ROW2 row;
    INITIALIZE_MIB_IPFORWARD_ROW(&row);
    row.InterfaceIndex = interface_index;
    row.DestinationPrefix.Ipv6.sin6_family = AF_INET6;
    const auto prefix_bytes = entry.prefix.to_v6().to_bytes();
    std::copy(prefix_bytes.begin(), prefix_bytes.end(),
              row.DestinationPrefix.Ipv6.sin6_addr.s6_addr);
    row.DestinationPrefixLength = entry.prefix_length;
    row.NextHop.Ipv6.sin6_family = AF_INET6;
    if (entry.gateway.is_v6()) {
        const auto hop_bytes = entry.gateway.to_v6().to_bytes();
        std::copy(hop_bytes.begin(), hop_bytes.end(), row.NextHop.Ipv6.sin6_addr.s6_addr);
        row.NextHop.Ipv6.sin6_scope_id =
            static_cast<DWORD>(entry.gateway.to_v6().scope_id());
    }
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Type = MIB_IPFORWARD_TYPE_INDIRECT;

    const auto status =
        install ? CreateIpForwardEntry2(&row) : DeleteIpForwardEntry2(&row);
    if (status == NO_ERROR) return {true};
    if (install && status == ERROR_ENTRY_ALREADY_EXISTS) {
        return {true, true, false, ""}; // already in place: desired state reached
    }
    if (!install && status == ERROR_ENTRY_NOT_FOUND) {
        return {true, false, true, ""}; // nothing to remove: idempotent success
    }
    const auto operation =
        install ? "CreateIpForwardEntry2" : "DeleteIpForwardEntry2";
    return {false, false, false, win_error(operation, status)};
}

// Subnet mask for a v4 prefix length, in network byte order.
std::uint32_t netmask_nbo(const std::uint8_t prefix_length) {
    const auto host_bits = 32u - static_cast<unsigned>(prefix_length);
    const auto mask_host_order = (host_bits >= 32u) ? 0u : (~0u << host_bits);
    return htonl(mask_host_order);
}

routing::OperationResult apply(const bool install, const routing::RouteEntry& entry) {
    if (entry.prefix.is_v6()) {
        return apply_v6(install, entry);
    }
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

    const auto friendly_matches = [&guid](const wchar_t* value) {
        if (!value) return false;
        const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 1) return false;
        std::string utf8(static_cast<std::size_t>(size), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8.data(), size, nullptr, nullptr);
        utf8.resize(static_cast<std::size_t>(size - 1));
        return utf8 == guid;
    };
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        const bool guid_matches = adapter->AdapterName && std::string(adapter->AdapterName) == guid;
        if (!guid_matches && !friendly_matches(adapter->FriendlyName)) continue;
        for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            const auto ipv4 = unicast_ipv4(unicast);
            if (ipv4.is_v4()) return AdapterRouteInfo{ipv4, adapter->IfIndex};
        }
    }
    return std::nullopt;
}

std::optional<AdapterRouteInfo> find_adapter_ipv6(const std::string& guid) {
    // Query with GAA_FLAG_SKIP_ANYCAST/UNICAST filtering is not enabled; we
    // simply keep the first global or unique-local (ULA) IPv6 unicast and
    // skip link-local/loopback so the tunnel can actually route global IPv6.
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr, nullptr, &size)
            != ERROR_BUFFER_OVERFLOW || size == 0) {
        return std::nullopt;
    }
    std::vector<uint8_t> storage(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    if (GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr,
            adapters, &size) != NO_ERROR) {
        return std::nullopt;
    }

    const auto friendly_matches = [&guid](const wchar_t* value) {
        if (!value) return false;
        const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 1) return false;
        std::string utf8(static_cast<std::size_t>(size), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8.data(), size, nullptr, nullptr);
        utf8.resize(static_cast<std::size_t>(size - 1));
        return utf8 == guid;
    };
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        const bool guid_matches = adapter->AdapterName && std::string(adapter->AdapterName) == guid;
        if (!guid_matches && !friendly_matches(adapter->FriendlyName)) continue;
        for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            const auto ipv6 = unicast_ipv6(unicast);
            if (!ipv6.is_v6() || ipv6.is_loopback()) continue;
            if (ipv6.to_v6().is_link_local()) continue;
            if (ipv6.to_v6().is_multicast()) continue;
            return AdapterRouteInfo{ipv6, adapter->IfIndex};
        }
    }
    return std::nullopt;
}

// IPv6 default (::/0) gateway before the VPN takes over; used to pin IPv6
// peer transport out of a full-tunnel IPv6 default. Scans the IPv6 forward
// table (GetIpForwardTable2) for the lowest-metric non-excluded default row.
std::optional<AdapterRouteInfo> find_default_route_v6(const std::uint32_t excluded_ifindex) {
    MIB_IPFORWARDTABLE2* table = nullptr;
    if (GetIpForwardTable2(AF_INET6, &table) != NO_ERROR || !table) {
        return std::nullopt;
    }
    struct TableGuard {
        MIB_IPFORWARDTABLE2* t;
        ~TableGuard() { if (t) FreeMibTable(t); }
    } guard{table};

    const MIB_IPFORWARD_ROW2* best = nullptr;
    ULONG best_metric = 0xFFFFFFFFUL;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        if (excluded_ifindex != 0 && row.InterfaceIndex == excluded_ifindex) continue;
        if (row.DestinationPrefix.si_family != AF_INET6) continue;
        if (row.DestinationPrefixLength != 0) continue;   // not a default route
        if (!best || row.Metric < best_metric) {
            best = &row;
            best_metric = row.Metric;
        }
    }
    if (!best) return std::nullopt;

    AdapterRouteInfo info{};
    if (best->NextHop.si_family == AF_INET6) {
        asio::ip::address_v6::bytes_type hop{};
        std::copy(std::begin(best->NextHop.Ipv6.sin6_addr.s6_addr),
                  std::end(best->NextHop.Ipv6.sin6_addr.s6_addr), hop.begin());
        info.ipv4 = asio::ip::address(
            asio::ip::address_v6(hop, best->NextHop.Ipv6.sin6_scope_id));
    }
    info.interface_index = best->InterfaceIndex;
    return info;
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
