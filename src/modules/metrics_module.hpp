#ifndef PQVPN_METRICS_HPP
#define PQVPN_METRICS_HPP

#include <string>
#include <string_view>
#include <unordered_map>
#include <map>
#include <atomic>
#include <mutex>
#include <memory>
#include <iostream>
#include <vector>
#include <algorithm>
#include <limits>
#include <sstream>

namespace pqvpn::metrics {

class Histogram {
public:
    Histogram(std::vector<double> boundaries) : boundaries_(std::move(boundaries)) {
        std::sort(boundaries_.begin(), boundaries_.end());
        counts_.resize(boundaries_.size() + 1);
        for (auto& c : counts_) {
            c = std::make_shared<std::atomic<uint64_t>>(0);
        }
    }

    void observe(double value) {
        auto it = std::lower_bound(boundaries_.begin(), boundaries_.end(), value);
        size_t index = std::distance(boundaries_.begin(), it);
        counts_[index]->fetch_add(1, std::memory_order_relaxed);
    }

    std::map<double, uint64_t> get_counts() const {
        std::map<double, uint64_t> result;
        for (size_t i = 0; i < boundaries_.size(); ++i) {
            result[boundaries_[i]] = counts_[i]->load(std::memory_order_relaxed);
        }
        double inf = std::numeric_limits<double>::infinity();
        result[inf] = counts_[boundaries_.size()]->load(std::memory_order_relaxed);
        return result;
    }

    const std::vector<double>& boundaries() const { return boundaries_; }

private:
    std::vector<double> boundaries_;
    std::vector<std::shared_ptr<std::atomic<uint64_t>>> counts_;
};

class MetricsRegistry {
public:
    static MetricsRegistry& instance() {
        static MetricsRegistry registry;
        return registry;
    }

    void increment_counter(std::string_view name, uint64_t amount = 1) {
        get_or_create_counter(name).fetch_add(amount, std::memory_order_relaxed);
    }

    uint64_t get_counter(std::string_view name) const {
        auto it = counters_.find(std::string(name));
        if (it != counters_.end()) return it->second->load(std::memory_order_relaxed);
        return 0;
    }

    void set_gauge(std::string_view name, double value) {
        get_or_create_gauge(name).store(value, std::memory_order_relaxed);
    }

    double get_gauge(std::string_view name) const {
        auto it = gauges_.find(std::string(name));
        if (it != gauges_.end()) return it->second->load(std::memory_order_relaxed);
        return 0.0;
    }

    std::shared_ptr<Histogram> get_or_create_histogram(std::string_view name, const std::vector<double>& boundaries) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        auto it = histograms_.find(std::string(name));
        if (it != histograms_.end()) return it->second;
        auto hist = std::make_shared<Histogram>(boundaries);
        histograms_[std::string(name)] = hist;
        return hist;
    }

    std::unordered_map<std::string, double> get_snapshot() const {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        std::unordered_map<std::string, double> snapshot;
        for (const auto& [name, counter] : counters_) {
            snapshot[name] = static_cast<double>(counter->load(std::memory_order_relaxed));
        }
        for (const auto& [name, gauge] : gauges_) {
            snapshot[name] = gauge->load(std::memory_order_relaxed);
        }
        for (const auto& [name, hist] : histograms_) {
            auto counts = hist->get_counts();
            for (const auto& [boundary, count] : counts) {
                std::string key = "hist:" + name + ":" + (boundary == std::numeric_limits<double>::infinity() ? "inf" : std::to_string(boundary));
                snapshot[key] = static_cast<double>(count);
            }
        }
        return snapshot;
    }

    void dump_metrics() const {
        auto snapshot = get_snapshot();
        std::cout << "--- Metrics Dump ---\n";
        for (const auto& [name, value] : snapshot) {
            std::cout << "[Metric] " << name << ": " << value << "\n";
        }
        std::cout << "--------------------\n";
    }

private:
    MetricsRegistry() = default;
    mutable std::mutex registry_mutex_;
    std::unordered_map<std::string, std::shared_ptr<std::atomic<uint64_t>>> counters_;
    std::unordered_map<std::string, std::shared_ptr<std::atomic<double>>> gauges_;
    std::unordered_map<std::string, std::shared_ptr<Histogram>> histograms_;

    std::atomic<uint64_t>& get_or_create_counter(std::string_view name) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        auto it = counters_.find(std::string(name));
        if (it != counters_.end()) return *it->second;
        auto counter = std::make_shared<std::atomic<uint64_t>>(0);
        counters_[std::string(name)] = counter;
        return *counter;
    }

    std::atomic<double>& get_or_create_gauge(std::string_view name) {
        std::lock_guard<std::mutex> lock(registry_mutex_);
        auto it = gauges_.find(std::string(name));
        if (it != gauges_.end()) return *it->second;
        auto gauge = std::make_shared<std::atomic<double>>(0.0);
        gauges_[std::string(name)] = gauge;
        return *gauge;
    }
};

class NetworkAnalytics {
public:
    NetworkAnalytics() = default;

    void record_packet(std::string_view direction, uint64_t size) {
        auto& registry = MetricsRegistry::instance();
        if (direction == "sent") {
            registry.increment_counter("pqvpn_packets_sent_total", 1);
            registry.increment_counter("pqvpn_bytes_sent_total", size);
        } else if (direction == "recv") {
            registry.increment_counter("pqvpn_packets_recv_total", 1);
            registry.increment_counter("pqvpn_bytes_recv_total", size);
        }
    }

    void record_session_active(double value) {
        MetricsRegistry::instance().set_gauge("pqvpn_sessions_active", value);
    }

    void record_rekey() {
        MetricsRegistry::instance().increment_counter("pqvpn_rekeys_performed", 1);
    }

    void record_handshake_retry() {
        MetricsRegistry::instance().increment_counter("pqvpn_handshake_retries_total", 1);
    }

    void record_handshake_per_peer(std::string_view peer_hex) {
        std::string name = "pqvpn_handshakes_per_peer{peer=\"" + std::string(peer_hex) + "\"}";
        MetricsRegistry::instance().increment_counter(name, 1);
    }

    std::string export_prometheus() const {
        auto& registry = MetricsRegistry::instance();
        auto snapshot = registry.get_snapshot();
        std::stringstream ss;

        ss << "# HELP pqvpn_packets_sent_total Total packets sent\n";
        ss << "# TYPE pqvpn_packets_sent_total counter\n";
        ss << "pqvpn_packets_sent_total " << static_cast<uint64_t>(snapshot["pqvpn_packets_sent_total"]) << "\n";

        ss << "# HELP pqvpn_packets_recv_total Total packets received\n";
        ss << "# TYPE pqvpn_packets_recv_total counter\n";
        ss << "pqvpn_packets_recv_total " << static_cast<uint64_t>(snapshot["pqvpn_packets_recv_total"]) << "\n";

        ss << "# HELP pqvpn_bytes_sent_total Total bytes sent\n";
        ss << "# TYPE pqvpn_bytes_sent_total counter\n";
        ss << "pqvpn_bytes_sent_total " << static_cast<uint64_t>(snapshot["pqvpn_bytes_sent_total"]) << "\n";

        ss << "# HELP pqvpn_bytes_recv_total Total bytes received\n";
        ss << "# TYPE pqvpn_bytes_recv_total counter\n";
        ss << "pqvpn_bytes_recv_total " << static_cast<uint64_t>(snapshot["pqvpn_bytes_recv_total"]) << "\n";

        ss << "# HELP pqvpn_sessions_active Current active sessions\n";
        ss << "# TYPE pqvpn_sessions_active gauge\n";
        ss << "pqvpn_sessions_active " << snapshot["pqvpn_sessions_active"] << "\n";

        ss << "# HELP pqvpn_rekeys_performed Total key rotations\n";
        ss << "# TYPE pqvpn_rekeys_performed counter\n";
        ss << "pqvpn_rekeys_performed " << static_cast<uint64_t>(snapshot["pqvpn_rekeys_performed"]) << "\n";

        ss << "# HELP pqvpn_handshake_retries_total Total handshake retries\n";
        ss << "# TYPE pqvpn_handshake_retries_total counter\n";
        ss << "pqvpn_handshake_retries_total " << static_cast<uint64_t>(snapshot["pqvpn_handshake_retries_total"]) << "\n";

        ss << "# HELP pqvpn_handshakes_per_peer Handshake attempts per peer (labelled)\n";
        ss << "# TYPE pqvpn_handshakes_per_peer counter\n";

        for (const auto& [name, value] : snapshot) {
            if (name.find("pqvpn_handshakes_per_peer{") == 0) {
                ss << name << " " << static_cast<uint64_t>(value) << "\n";
            }
        }

        return ss.str();
    }
};

} // namespace pqvpn::metrics

#endif // PQVPN_METRICS_HPP
