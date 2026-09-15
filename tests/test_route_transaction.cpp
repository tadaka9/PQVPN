#include <catch2/catch_test_macros.hpp>

#include <asio.hpp>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "routing/route_transaction.hpp"

namespace {

// Records every backend call and can be scripted to fail at a chosen step, so
// the transaction logic is exercised without touching the system routing table.
struct ScriptedRouteBackend : pqvpn::routing::RouteBackend {
    std::vector<std::string> calls;
    int failing_install = -1; // 0-based index of the install call that hard-fails
    int failing_remove = -1;  // 0-based index of the remove call that hard-fails
    bool removes_report_absent = false;
    std::set<int> already_present_installs; // install indices reported as pre-existing

    int installs = 0;
    int removals = 0;

    static std::string key(const pqvpn::routing::RouteEntry& entry) {
        return entry.prefix.to_string() + "/" + std::to_string(entry.prefix_length);
    }

    pqvpn::routing::OperationResult install(const pqvpn::routing::RouteEntry& entry) override {
        calls.push_back("install " + key(entry));
        const int index = installs++;
        if (index == failing_install) return {false, false, false, "scripted failure"};
        return {true, already_present_installs.count(index) != 0, false, ""};
    }

    pqvpn::routing::OperationResult remove(const pqvpn::routing::RouteEntry& entry) override {
        calls.push_back("remove " + key(entry));
        if (removals++ == failing_remove) return {false, false, false, "scripted failure"};
        return {true, false, removes_report_absent, ""};
    }
};

pqvpn::routing::RouteEntry entry(const std::string& prefix, const int length,
                                 const std::string& gateway = "10.9.8.7") {
    return pqvpn::routing::RouteEntry{asio::ip::make_address(prefix),
        static_cast<std::uint8_t>(length), asio::ip::make_address(gateway), 42};
}

} // namespace

TEST_CASE("commit installs every entry in plan order", "[routing]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::RouteTransaction plan;
    plan.add(entry("10.0.0.0", 8));
    plan.add(entry("192.168.5.0", 24));

    const auto report = plan.commit(backend);
    REQUIRE(report.committed);
    REQUIRE(report.error.empty());
    REQUIRE(report.rolled_back.empty());
    REQUIRE(backend.calls == std::vector<std::string>{
        "install 10.0.0.0/8", "install 192.168.5.0/24"});
}

TEST_CASE("commit rolls back installed entries when one fails", "[routing]") {
    ScriptedRouteBackend backend;
    backend.failing_install = 1; // the second install hard-fails
    pqvpn::routing::RouteTransaction plan;
    plan.add(entry("10.0.0.0", 8));
    plan.add(entry("192.168.5.0", 24));
    plan.add(entry("172.16.0.0", 12));

    const auto report = plan.commit(backend);
    REQUIRE_FALSE(report.committed);
    REQUIRE(report.failed_index == 1);
    REQUIRE(report.error.find("scripted failure") != std::string::npos);
    // The first entry is rolled back in reverse order; the third was never installed.
    REQUIRE(report.rolled_back.size() == 1);
    REQUIRE(report.rolled_back.front().prefix.to_string() == "10.0.0.0");
    REQUIRE(backend.calls == std::vector<std::string>{
        "install 10.0.0.0/8", "install 192.168.5.0/24", "remove 10.0.0.0/8"});
}

TEST_CASE("commit on an empty plan succeeds without touching the backend", "[routing]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::RouteTransaction plan;

    const auto report = plan.commit(backend);
    REQUIRE(report.committed);
    REQUIRE(backend.calls.empty());
}

TEST_CASE("default-route entries with an unspecified prefix are accepted", "[routing]") {
    // main.cpp installs exactly this row for a TAP adapter that has IPv4:
    // destination 0.0.0.0, zero mask (prefix length 0 = the default route),
    // gateway = the adapter address. A /32 would match only 0.0.0.0 itself.
    ScriptedRouteBackend backend;
    pqvpn::routing::RouteTransaction plan;
    const auto tap_route = entry("0.0.0.0", 0, "10.8.0.2");
    REQUIRE(tap_route.valid());
    plan.add(tap_route);

    // The IPv6 default-route shape is equally legitimate.
    const auto v6_default = entry("::", 0, "fe80::1");
    REQUIRE(v6_default.valid());
    plan.add(v6_default);

    const auto report = plan.commit(backend);
    REQUIRE(report.committed);
    REQUIRE(backend.calls == std::vector<std::string>{
        "install 0.0.0.0/0", "install ::/0"});
}

TEST_CASE("route entries still need a concrete gateway of the prefix family", "[routing]") {
    pqvpn::routing::RouteTransaction plan;

    // Unspecified gateway: nowhere to send the traffic.
    REQUIRE_THROWS_AS(plan.add(entry("10.0.0.0", 8, "0.0.0.0")), std::invalid_argument);
    REQUIRE_THROWS_AS(plan.add(entry("::", 64, "::")), std::invalid_argument);

    // Mixed address families cannot form a route.
    REQUIRE_THROWS_AS(plan.add(entry("10.0.0.0", 8, "fe80::1")), std::invalid_argument);
    REQUIRE_THROWS_AS(plan.add(entry("2001:db8::", 64, "10.9.8.7")), std::invalid_argument);

    // Prefix length beyond the family maximum.
    REQUIRE_THROWS_AS(plan.add(entry("10.0.0.0", 33)), std::invalid_argument);
}

TEST_CASE("remove_all treats absent owned entries as success", "[routing]") {
    ScriptedRouteBackend backend;
    backend.removes_report_absent = true;
    pqvpn::routing::RouteTransaction plan;
    plan.add(entry("10.0.0.0", 8));
    plan.add(entry("192.168.5.0", 24));

    REQUIRE(plan.commit(backend).committed); // entries are now owned by the transaction
    const auto report = plan.remove_all(backend);
    REQUIRE(report.complete);
    REQUIRE(report.removed == 0);
    REQUIRE(report.already_absent == 2);
    REQUIRE(report.error.empty());
}

TEST_CASE("remove_all keeps cleaning up past a hard failure", "[routing]") {
    ScriptedRouteBackend backend;
    backend.failing_remove = 0; // the first removal hard-fails, the second succeeds
    pqvpn::routing::RouteTransaction plan;
    plan.add(entry("10.0.0.0", 8));
    plan.add(entry("192.168.5.0", 24));

    REQUIRE(plan.commit(backend).committed); // entries are now owned by the transaction
    const auto report = plan.remove_all(backend);
    REQUIRE_FALSE(report.complete);
    REQUIRE(report.error.find("scripted failure") != std::string::npos);
    REQUIRE(report.removed == 1);
    // Both removals were attempted despite the first failing (after the two installs).
    const auto& c = backend.calls;
    REQUIRE(c.size() == 4u);
    REQUIRE(c[2] == "remove 10.0.0.0/8");
    REQUIRE(c[3] == "remove 192.168.5.0/24");
}

TEST_CASE("invalid entries are rejected when added to a plan", "[routing]") {
    pqvpn::routing::RouteTransaction plan;
    // Unspecified gateway.
    REQUIRE_THROWS_AS(plan.add(pqvpn::routing::RouteEntry{
        asio::ip::make_address("10.0.0.0"), 8, asio::ip::address{}, 42}),
        std::invalid_argument);
    // Prefix length beyond the address family width.
    REQUIRE_THROWS_AS(plan.add(entry("10.0.0.0", 33)), std::invalid_argument);

    REQUIRE(plan.empty());
}

TEST_CASE("cleanup does not delete pre-existing routes", "[routing]") {
    ScriptedRouteBackend backend;
    // The first route already exists in the table (admin-configured); the
    // second is created by this transaction.
    backend.already_present_installs.insert(0);
    pqvpn::routing::RouteTransaction plan;
    plan.add(entry("10.0.0.0", 8));      // index 0: already present
    plan.add(entry("192.168.5.0", 24));  // index 1: created by us

    REQUIRE(plan.commit(backend).committed);

    const auto report = plan.remove_all(backend);
    REQUIRE(report.complete);
    REQUIRE(report.removed == 1);          // only the route we created
    REQUIRE(report.already_absent == 0);
    // The pre-existing route (index 0) must never be removed.
    for (const auto& call : backend.calls) {
        REQUIRE(call.find("remove 10.0.0.0/8") == std::string::npos);
    }
    REQUIRE(backend.calls.back() == "remove 192.168.5.0/24");
}

TEST_CASE("rollback leaves already-present routes when a later install fails", "[routing]") {
    ScriptedRouteBackend backend;
    // index 0 already present, index 1 created by us, index 2 hard-fails.
    backend.already_present_installs.insert(0);
    backend.failing_install = 2;
    pqvpn::routing::RouteTransaction plan;
    plan.add(entry("10.0.0.0", 8));      // index 0: already present
    plan.add(entry("192.168.5.0", 24));  // index 1: created by us
    plan.add(entry("172.16.0.0", 12));   // index 2: fails

    const auto report = plan.commit(backend);
    REQUIRE_FALSE(report.committed);
    REQUIRE(report.failed_index == 2);
    // Only the route we created (index 1) is rolled back; the pre-existing one
    // (index 0) and the failed one (index 2, never installed) are untouched.
    REQUIRE(report.rolled_back.size() == 1u);
    REQUIRE(report.rolled_back.front().prefix.to_string() == "192.168.5.0");
    for (const auto& call : backend.calls) {
        REQUIRE(call.find("remove 10.0.0.0/8") == std::string::npos);
    }
}

TEST_CASE("remove_all releases ownership so a later pass cannot delete recreated routes", "[routing]") {
    ScriptedRouteBackend backend;
    pqvpn::routing::RouteTransaction plan;
    plan.add(entry("10.0.0.0", 8));
    REQUIRE(plan.commit(backend).committed);

    const auto first = plan.remove_all(backend);
    REQUIRE(first.complete);
    REQUIRE(first.removed == 1);

    // Ownership is gone: an administrator may have recreated the route in the
    // meantime, and a second cleanup pass must not touch the table again.
    const std::size_t calls_before = backend.calls.size();
    const auto second = plan.remove_all(backend);
    REQUIRE(second.complete);
    REQUIRE(second.removed == 0);
    REQUIRE(second.already_absent == 0);
    REQUIRE(backend.calls.size() == calls_before); // no further backend activity
}
