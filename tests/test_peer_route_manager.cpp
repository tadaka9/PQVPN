#include <catch2/catch_test_macros.hpp>

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "modules/node_module.hpp"
#include "routing/peer_route_manager.hpp"

namespace {

// Records every backend call (and the entries it saw) so the manager logic is
// exercised without touching a real routing table. Mirrors the scripted
// backend in test_route_transaction.cpp, extended with entry capture and a
// removable failure point for remove().
struct ScriptedRouteBackend : pqvpn::routing::RouteBackend {
    std::vector<std::string> calls;
    std::vector<pqvpn::routing::RouteEntry> installed_entries;
    int failing_remove = -1; // 0-based index of the remove call that hard-fails

    int removals = 0;

    static std::string key(const pqvpn::routing::RouteEntry& entry) {
        return entry.prefix.to_string() + "/" + std::to_string(entry.prefix_length);
    }

    pqvpn::routing::OperationResult install(const pqvpn::routing::RouteEntry& entry) override {
        calls.push_back("install " + key(entry));
        installed_entries.push_back(entry);
        return {true, false, false, ""};
    }

    pqvpn::routing::OperationResult remove(const pqvpn::routing::RouteEntry& entry) override {
        calls.push_back("remove " + key(entry));
        if (removals++ == failing_remove) return {false, false, false, "scripted failure"};
        return {true, false, false, ""};
    }
};

asio::ip::udp::endpoint peer_endpoint(const std::string& address, const unsigned short port) {
    return asio::ip::udp::endpoint(asio::ip::make_address(address), port);
}

pqvpn::routing::PeerRouteManager::PhysicalGateway gateway(
        const std::string& address, const std::uint32_t ifindex = 7) {
    return {asio::ip::make_address(address), ifindex};
}

} // namespace

TEST_CASE("add_peer installs a /32 host route through the physical gateway", "[routing][peerroutes]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::PeerRouteManager manager(backend);
    REQUIRE_FALSE(manager.has_physical_gateway());
    manager.set_physical_gateway(gateway("192.168.1.1"));

    const auto peer = peer_endpoint("203.0.113.20", 443);
    const auto result = manager.add_peer(peer);

    REQUIRE(result.ok);
    REQUIRE(backend.calls == std::vector<std::string>{"install 203.0.113.20/32"});
    REQUIRE(backend.installed_entries.size() == 1);
    const auto& entry = backend.installed_entries.front();
    REQUIRE(entry.prefix.to_string() == "203.0.113.20");
    REQUIRE(entry.prefix_length == 32); // host route, not a network prefix
    REQUIRE(entry.gateway.to_string() == "192.168.1.1");
    REQUIRE(entry.interface_index == 7);
}

TEST_CASE("re-adding an already-excluded peer is idempotent and does not duplicate bookkeeping", "[routing][peerroutes]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::PeerRouteManager manager(backend);
    manager.set_physical_gateway(gateway("192.168.1.1"));

    const auto peer = peer_endpoint("203.0.113.20", 443);
    REQUIRE(manager.add_peer(peer).ok);
    // The backend install is idempotent by contract, so a second add is safe...
    REQUIRE(manager.add_peer(peer).ok);

    // ...but the manager owns exactly one exclusion for that peer: rollback
    // must remove it once, not twice.
    const auto report = manager.remove_all();
    REQUIRE(report.complete);
    REQUIRE(report.removed == 1);
    REQUIRE(backend.calls.size() == 3); // install, install, remove
}

TEST_CASE("remove_all unwinds exclusions in reverse insertion order", "[routing][peerroutes]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::PeerRouteManager manager(backend);
    manager.set_physical_gateway(gateway("192.168.1.1"));

    const auto a = peer_endpoint("203.0.113.10", 443);
    const auto b = peer_endpoint("203.0.113.20", 443);
    const auto c = peer_endpoint("203.0.113.30", 443);
    REQUIRE(manager.add_peer(a).ok);
    REQUIRE(manager.add_peer(b).ok);
    REQUIRE(manager.add_peer(c).ok);

    const auto report = manager.remove_all();
    REQUIRE(report.complete);
    REQUIRE(report.removed == 3);
    // Most recently added first: shutdown unwinds the route set as built.
    REQUIRE(backend.calls == std::vector<std::string>{
        "install 203.0.113.10/32", "install 203.0.113.20/32", "install 203.0.113.30/32",
        "remove 203.0.113.30/32", "remove 203.0.113.20/32", "remove 203.0.113.10/32"});

    // A second pass finds nothing owned to remove.
    REQUIRE(manager.remove_all().complete);
}

TEST_CASE("add_peer fails closed without a physical gateway and never touches the backend", "[routing][peerroutes]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::PeerRouteManager manager(backend);

    const auto result = manager.add_peer(peer_endpoint("203.0.113.20", 443));
    REQUIRE_FALSE(result.ok);
    REQUIRE_FALSE(result.error.empty());
    REQUIRE(backend.calls.empty()); // no route may be installed without a gateway
}

TEST_CASE("address-family mismatches are rejected before any backend call", "[routing][peerroutes]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::PeerRouteManager manager(backend);
    manager.set_physical_gateway(gateway("192.168.1.1"));

    // IPv6 peer, v4 gateway: this backend cannot express that route.
    REQUIRE_FALSE(manager.add_peer(peer_endpoint("2001:db8::1", 443)).ok);

    ScriptedRouteBackend v6_backend;
    pqvpn::routing::PeerRouteManager v6_manager(v6_backend);
    v6_manager.set_physical_gateway(gateway("fe80::1"));
    // v4 peer, v6 gateway: same mismatch in the other direction.
    REQUIRE_FALSE(v6_manager.add_peer(peer_endpoint("203.0.113.20", 443)).ok);

    REQUIRE(backend.calls.empty());
    REQUIRE(v6_backend.calls.empty());
}

TEST_CASE("remove_peer for an untracked peer reports idempotent success without touching the backend", "[routing][peerroutes]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::PeerRouteManager manager(backend);
    manager.set_physical_gateway(gateway("192.168.1.1"));

    const auto result = manager.remove_peer(peer_endpoint("198.51.100.7", 443));
    REQUIRE(result.ok);
    REQUIRE(result.not_found); // "already gone" is the desired state
    REQUIRE(backend.calls.empty());
}

TEST_CASE("remove_all on an empty manager succeeds without touching the backend", "[routing][peerroutes]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::PeerRouteManager manager(backend);
    manager.set_physical_gateway(gateway("192.168.1.1"));

    const auto report = manager.remove_all();
    REQUIRE(report.complete);
    REQUIRE(report.removed == 0);
    REQUIRE(report.already_absent == 0);
    REQUIRE(report.error.empty());
    REQUIRE(backend.calls.empty());
}

TEST_CASE("a hard remove failure keeps the exclusion tracked so remove_all retries it", "[routing][peerroutes]") {
    ScriptedRouteBackend backend;
    backend.failing_remove = 0; // the first removal (remove_peer) hard-fails
    pqvpn::routing::PeerRouteManager manager(backend);
    manager.set_physical_gateway(gateway("192.168.1.1"));

    const auto peer = peer_endpoint("203.0.113.20", 443);
    REQUIRE(manager.add_peer(peer).ok);

    const auto failed = manager.remove_peer(peer);
    REQUIRE_FALSE(failed.ok);

    // The exclusion is still owned: remove_all must retry it (and this time
    // the scripted failure point has passed, so it succeeds).
    const auto report = manager.remove_all();
    REQUIRE(report.complete);
    REQUIRE(report.removed == 1);
}

TEST_CASE("HELLO registration notifies the peer-route hook with add=true", "[routing][peerroutes][node]") {
    pqvpn::PQVPNNode node("test_config.toml");
    std::vector<std::pair<asio::ip::udp::endpoint, bool>> notifications;
    node.set_peer_route_hook([&notifications](const asio::ip::udp::endpoint& address, const bool add) {
        notifications.emplace_back(address, add);
    });

    const auto address = peer_endpoint("198.51.100.23", 51820);
    std::map<std::string, std::string> hello;
    hello["peerid"] = "aabbccddeeff00112233445566778899";

    REQUIRE(node.register_peer_from_hello(hello, address).has_value());
    REQUIRE(notifications.size() == 1);
    REQUIRE(notifications.front().first == address);
    REQUIRE(notifications.front().second); // add=true: the peer is now known
}

TEST_CASE("pruning a stale session notifies the hook with add=false and drops the session", "[routing][peerroutes][node]") {
    pqvpn::PQVPNNode node("test_config.toml");
    std::vector<std::pair<asio::ip::udp::endpoint, bool>> notifications;
    node.set_peer_route_hook([&notifications](const asio::ip::udp::endpoint& address, const bool add) {
        notifications.emplace_back(address, add);
    });

    const auto now = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Stale session: past SESSION_TIMEOUT, so maintenance_tick must prune it.
    auto stale = std::make_shared<pqvpn::PQVPNNode::Session>();
    stale->session_id = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    stale->remote_addr = peer_endpoint("203.0.113.20", 443);
    stale->state = pqvpn::PQVPNNode::SessionState::ESTABLISHED;
    stale->last_activity = now - pqvpn::PQVPNNode::SESSION_TIMEOUT - 60.0;
    node.sessions_by_peer_id[{0xAA, 0xBB}] = stale;

    // Fresh session: must survive the same tick untouched (and unnotified).
    auto fresh = std::make_shared<pqvpn::PQVPNNode::Session>();
    fresh->session_id = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF1};
    fresh->remote_addr = peer_endpoint("203.0.113.21", 443);
    fresh->state = pqvpn::PQVPNNode::SessionState::ESTABLISHED;
    fresh->last_activity = now;
    node.sessions_by_peer_id[{0xCC, 0xDD}] = fresh;

    asio::io_context& io = node.get_io_context();
    bool ticked = false;
    asio::co_spawn(io, [&]() -> asio::awaitable<void> {
        co_await node.maintenance_tick();
        ticked = true;
    }(), asio::detached);
    io.run();

    REQUIRE(ticked);
    REQUIRE(node.sessions_by_peer_id.size() == 1); // only the fresh one remains
    REQUIRE(notifications.size() == 1);
    REQUIRE(notifications.front().first == stale->remote_addr);
    REQUIRE_FALSE(notifications.front().second); // add=false: exclusion rolled back
}
