#include "geographic_failover.hpp"
#include <catch2/catch_test_macros.hpp>
#include <vector>
#include <cstdint>

TEST_CASE("GeographicFailover initialization", "[geographic_failover]") {
    GeographicFailover failover;
    REQUIRE(failover.get_primary_path() == std::nullopt);
    REQUIRE(failover.get_backup_paths().empty());
    REQUIRE(failover.get_current_path_idx() == 0);
    REQUIRE(failover.get_last_failover() == 0.0);
}

TEST_CASE("GeographicFailover add_backup_paths", "[geographic_failover]") {
    GeographicFailover failover;
    std::vector<uint8_t> path1 = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> path2 = {0xCA, 0xFE, 0xBA, 0xBE};
    std::vector<std::vector<uint8_t>> paths = {path1, path2};

    failover.add_backup_paths(paths);

    REQUIRE(failover.get_backup_paths().size() == 2);
    REQUIRE(failover.get_backup_paths()[0] == path1);
    REQUIRE(failover.get_backup_paths()[1] == path2);
    REQUIRE(failover.get_path_health().at(0) == 1.0);
    REQUIRE(failover.get_path_health().at(1) == 1.0);
}

TEST_CASE("GeographicFailover get_active_path", "[geographic_failover]") {
    GeographicFailover failover;
    std::vector<uint8_t> primary = {0x01, 0x02};
    std::vector<uint8_t> backup1 = {0xAA, 0xBB};
    std::vector<uint8_t> backup2 = {0xCC, 0xDD};

    failover.set_primary_path(primary);
    failover.add_backup_paths({{backup1}, {backup2}});

    // Index 0 is primary
    REQUIRE(failover.get_active_path() == primary);

    // Index 1 is backup[0]
    failover.set_current_path_idx(1);
    REQUIRE(failover.get_active_path() == backup1);

    // Index 2 is backup[1]
    failover.set_current_path_idx(2);
    REQUIRE(failover.get_active_path() == backup2);

    // Index 3 is out of bounds
    failover.set_current_path_idx(3);
    REQUIRE(failover.get_active_path() == std::nullopt);
}
