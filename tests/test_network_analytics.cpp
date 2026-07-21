#include "metrics_module.hpp"
#include <cassert>
#include <iostream>

int main() {
    pqvpn::metrics::NetworkAnalytics analytics;

    // Test record_packet for "sent" direction
    analytics.record_packet("sent", 100);
    analytics.record_packet("sent", 200);

    auto& registry = pqvpn::metrics::MetricsRegistry::instance();
    assert(registry.get_counter("pqvpn_packets_sent_total") == 2);
    assert(registry.get_counter("pqvpn_bytes_sent_total") == 300);

    // Test record_packet for "recv" direction
    analytics.record_packet("recv", 50);
    assert(registry.get_counter("pqvpn_packets_recv_total") == 1);
    assert(registry.get_counter("pqvpn_bytes_recv_total") == 50);

    std::cout << "NetworkAnalytics.record_packet tests passed!" << std::endl;
    return 0;
}
