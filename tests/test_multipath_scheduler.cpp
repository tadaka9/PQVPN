#include <catch2/catch_test_macros.hpp>
#include "multipath_scheduler.hpp"

TEST_CASE("multipath keeps flow affinity and excludes congested paths", "[multipath]") {
    using namespace pqvpn::multipath;
    std::vector<PathState> paths{{"a", 20, 1000, 1'000'000'000, 0, 10, true},
                                 {"b", 30, 1000, 1'000'000'000, 0, 10, true}};
    const auto first = rank_paths("tcp/10.0.0.1/443/10.0.0.2/40000", paths);
    REQUIRE(first.size() == 2);
    CHECK(rank_paths("tcp/10.0.0.1/443/10.0.0.2/40000", paths) == first);
    for (auto& path : paths) if (path.peer_id == first.front()) path.inflight = path.congestion_window;
    const auto failover = rank_paths("tcp/10.0.0.1/443/10.0.0.2/40000", paths);
    REQUIRE(failover.size() == 1);
    CHECK(failover.front() == first.back());
}

TEST_CASE("reorder buffer emits once in order and stays bounded", "[multipath]") {
    using namespace pqvpn::multipath;
    ReorderBuffer buffer(7, 4, 16);
    REQUIRE(buffer.insert(8, {8})->empty());
    REQUIRE(buffer.buffered_packets() == 1);
    const auto ready = buffer.insert(7, {7});
    REQUIRE(ready);
    REQUIRE(*ready == std::vector<std::vector<std::uint8_t>>{{7}, {8}});
    CHECK(buffer.next_sequence() == 9);
    CHECK_FALSE(buffer.insert(8, {8}));
    CHECK_FALSE(buffer.insert(13, {13}));
    CHECK(buffer.buffered_bytes() == 0);
}
