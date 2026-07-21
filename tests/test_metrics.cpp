#include <catch2/catch_test_macros.hpp>
#include "metrics_module.hpp"
#include <thread>
#include <vector>

using namespace pqvpn::metrics;

TEST_CASE("MetricsRegistry - Counters", "[metrics]") {
    auto& registry = MetricsRegistry::instance();

    SECTION("Increment counter") {
        registry.increment_counter("test_counter", 5);
        REQUIRE(registry.get_counter("test_counter") == 5);

        registry.increment_counter("test_counter", 10);
        REQUIRE(registry.get_counter("test_counter") == 15);
    }

    SECTION("Counter default increment is 1") {
        registry.increment_counter("default_inc");
        REQUIRE(registry.get_counter("default_inc") == 1);
    }

    SECTION("Non-existent counter returns 0") {
        REQUIRE(registry.get_counter("non_existent") == 0);
    }
}

TEST_CASE("MetricsRegistry - Gauges", "[metrics]") {
    auto& registry = MetricsRegistry::instance();

    SECTION("Set and get gauge") {
        registry.set_gauge("test_gauge", 42.5);
        REQUIRE(registry.get_gauge("test_gauge") == 42.5);

        registry.set_gauge("test_gauge", 10.0);
        REQUIRE(registry.get_gauge("test_gauge") == 10.0);
    }

    SECTION("Non-existent gauge returns 0.0") {
        REQUIRE(registry.get_gauge("non_existent_gauge") == 0.0);
    }
}

TEST_CASE("MetricsRegistry - Snapshot", "[metrics]") {
    auto& registry = MetricsRegistry::instance();

    // Reset/Setup for snapshot test
    registry.increment_counter("snap_counter", 10);
    registry.set_gauge("snap_gauge", 5.5);

    SECTION("Snapshot captures current state") {
        auto snapshot = registry.get_snapshot();
        REQUIRE(snapshot["snap_counter"] == 10.0);
        REQUIRE(snapshot["snap_gauge"] == 5.5);
    }
}

TEST_CASE("MetricsRegistry - Concurrency", "[metrics]") {
    auto& registry = MetricsRegistry::instance();
    const int num_threads = 10;
    const int increments_per_thread = 100;
    std::string counter_name = "concurrent_counter";

    // Reset counter (rough way to reset)
    uint64_t current = registry.get_counter(counter_name);
    if (current > 0) {
        registry.increment_counter(counter_name, -static_cast<uint64_t>(current));
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&registry, counter_name, increments_per_thread]() {
            for (int j = 0; j < increments_per_thread; ++j) {
                registry.increment_counter(counter_name);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    REQUIRE(registry.get_counter(counter_name) == (num_threads * increments_per_thread));
}
