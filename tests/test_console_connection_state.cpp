#include <catch2/catch_test_macros.hpp>
#include "console/connection_state.hpp"
using namespace pqvpn::console;

TEST_CASE("Console never claims protection from a running process alone", "[console]") {
    CHECK(connection_phase({true, false, false}) == ConnectionPhase::Connecting);
    CHECK(connection_phase({true, false, true}) == ConnectionPhase::Connecting);
    CHECK(connection_phase({true, true, false}) == ConnectionPhase::Securing);
    CHECK(connection_phase({true, true, true}) == ConnectionPhase::Protected);
}
TEST_CASE("Relay and stale readiness have distinct console states", "[console]") {
    CHECK(connection_phase({true, true, false, true}) == ConnectionPhase::Relay);
    CHECK(connection_phase({false, true, true}) == ConnectionPhase::Disconnected);
    CHECK(connection_phase({true, true, true, false, true}) == ConnectionPhase::Stopping);
    CHECK(connection_phase({true, true, true, false, false, true}) == ConnectionPhase::Failed);
    CHECK(connection_phase({false, false, false, false, false, true}) == ConnectionPhase::Failed);
    CHECK(phase_color(ConnectionPhase::Relay) == phase_color(ConnectionPhase::Protected));
    CHECK(phase_color(ConnectionPhase::Connecting) != phase_color(ConnectionPhase::Protected));
}
