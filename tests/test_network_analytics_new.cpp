#include <catch2/catch_test_macros.hpp>
#include "metrics_module.hpp"

TEST_CASE("NetworkAnalytics Prometheus Export", "[metrics]") {
    pqvpn::metrics::NetworkAnalytics analytics;
    auto& registry = pqvpn::metrics::MetricsRegistry::instance();

    // Reset metrics for clean test state (if possible, otherwise we just add to existing)
    analytics.record_packet("sent", 100);
    analytics.record_packet("recv", 200);
    analytics.record_session_active(5.0);
    analytics.record_rekey();
    analytics.record_handshake_retry();
    analytics.record_handshake_per_peer("abcdef12");

    std::string output = analytics.export_prometheus();

    // Verify specific lines exist in the exported string
    CHECK(output.find("pqvpn_packets_sent_total") != std::string::npos);
    CHECK(output.find("pqvpn_packets_recv_total") != std::string::npos);
    CHECK(output.find("pqvpn_bytes_sent_total 100") != std::string::npos);
    CHECK(output.find("pqvpn_bytes_recv_total 200") != std::string::npos);
    CHECK(output.find("pqvpn_sessions_active 5") != std::string::npos);
    CHECK(output.find("pqvpn_rekeys_performed 1") != std::string::npos);
    CHECK(output.find("pqvpn_handshake_retries_total 1") != std::string::npos);
    CHECK(output.find("pqvpn_handshakes_per_peer{peer=\"abcdef12\"} 1") != std::string::npos);
}
