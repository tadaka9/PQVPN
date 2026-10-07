#include <catch2/catch_test_macros.hpp>

#include "adaptive_transport.hpp"

using namespace std::chrono_literals;
using namespace pqvpn::transport;

TEST_CASE("PQTP frames preserve encrypted datagrams", "[transport][pqt]") {
    const Frame input{Lane::Tcp, 0x10203040u, {0, 1, 2, 3, 255}};
    const auto wire = encode_frame(input);
    const auto output = decode_frame(wire);
    REQUIRE(output.has_value());
    CHECK(output->lane == Lane::Tcp);
    CHECK(output->sequence == input.sequence);
    CHECK(output->payload == input.payload);

    auto truncated = wire;
    truncated.pop_back();
    CHECK_FALSE(decode_frame(truncated).has_value());
}

TEST_CASE("adaptive transport uses hysteresis for UDP and TCP", "[transport][adaptive]") {
    AdaptiveConfig config;
    config.enabled = true;
    config.minimum_dwell_ms = 1000;
    config.failure_switch_count = 2;
    config.recovery_probe_count = 3;
    const auto start = AdaptiveController::Clock::time_point{};
    AdaptiveController controller(config, start);

    CHECK(controller.observe({.send_failed=true}, start + 1100ms).lane == Lane::Udp);
    const auto fallback = controller.observe({.send_failed=true}, start + 1200ms);
    CHECK(fallback.lane == Lane::Tcp);
    CHECK(fallback.changed);

    CHECK(controller.observe({}, start + 2300ms).lane == Lane::Tcp);
    CHECK(controller.observe({}, start + 2400ms).lane == Lane::Tcp);
    const auto recovered = controller.observe({}, start + 2500ms);
    CHECK(recovered.lane == Lane::Udp);
    CHECK(recovered.changed);
}

TEST_CASE("manual transport modes never autoswitch", "[transport][adaptive]") {
    AdaptiveConfig tcp;
    tcp.enabled = true;
    tcp.mode = Mode::TcpOnly;
    AdaptiveController controller(tcp);
    CHECK(controller.observe({}).lane == Lane::Tcp);
    CHECK_FALSE(controller.observe({.udp_blocked=true}).changed);
}
