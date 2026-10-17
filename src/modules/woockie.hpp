#pragma once

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>

namespace pqvpn::woockie {

// A Woockie is a capability address, not a web URL:
//   woockie://<authenticated-peer-id>/<service>/<resource-path>
// The peer identity replaces DNS/host/port. Resolution is allowed only through
// an already authenticated PQVPN session and the named service must explicitly
// opt in; parsing never performs I/O.
struct Address {
    std::string peer_id;
    std::string service;
    std::string resource;
};

inline bool safe_component(const std::string_view value, const bool slash_allowed) {
    if (value.empty() || value.size() > 192 || value.front() == '/' || value.back() == '/') return false;
    bool previous_slash = false;
    for (const unsigned char ch : value) {
        const bool slash = ch == '/';
        if (!(std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-' || (slash_allowed && slash)) ||
            (slash && previous_slash)) return false;
        previous_slash = slash;
    }
    return value.find("..") == std::string_view::npos;
}

inline std::optional<Address> parse(const std::string_view input) {
    constexpr std::string_view scheme = "woockie://";
    if (input.size() > 512 || !input.starts_with(scheme) ||
        input.find_first_of("?#@\\") != std::string_view::npos) return std::nullopt;
    const auto body = input.substr(scheme.size());
    const auto peer_end = body.find('/');
    if (peer_end != 64) return std::nullopt;
    Address result;
    result.peer_id.assign(body.substr(0, peer_end));
    if (!std::all_of(result.peer_id.begin(), result.peer_id.end(), [](const unsigned char ch) {
            return std::isxdigit(ch) != 0;
        })) return std::nullopt;
    std::transform(result.peer_id.begin(), result.peer_id.end(), result.peer_id.begin(),
        [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    const auto remainder = body.substr(peer_end + 1);
    const auto service_end = remainder.find('/');
    const auto service = service_end == std::string_view::npos ? remainder : remainder.substr(0, service_end);
    if (!safe_component(service, false) || service.size() > 32) return std::nullopt;
    result.service.assign(service);
    std::transform(result.service.begin(), result.service.end(), result.service.begin(),
        [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (result.service != "strangenet" && result.service != "asgard" && result.service != "node")
        return std::nullopt;
    if (service_end != std::string_view::npos) {
        const auto resource = remainder.substr(service_end + 1);
        if (!safe_component(resource, true)) return std::nullopt;
        result.resource.assign(resource);
    }
    return result;
}

inline std::string canonical(const Address& address) {
    auto value = std::string{"woockie://"} + address.peer_id + '/' + address.service;
    if (!address.resource.empty()) value += '/' + address.resource;
    return value;
}

} // namespace pqvpn::woockie
