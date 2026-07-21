#ifndef GEOGRAPHIC_FAILOVER_HPP
#define GEOGRAPHIC_FAILOVER_HPP

#include <vector>
#include <map>
#include <optional>
#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include "logging_module.hpp"

/**
 * @brief Geographic Redundance and Failover Manager.
 * Corresponds to GeographicFailover in main.py.
 */
class GeographicFailover {
public:
    /**
     * @brief Initializes the geographic failover manager with default state.
     * Corresponds to GeographicFailover.__init__ in main.py.
     */
    GeographicFailover()
        : primary_path(std::nullopt)
        , backup_paths({})
        , path_health({})
        , current_path_idx(0)
        , last_failover(0.0)
    {}

    /**
     * @brief Add backup paths.
     * Corresponds to GeographicFailover.add_backup_path in main.py.
     */
    void add_backup_paths(const std::vector<std::vector<uint8_t>>& paths) {
        std::stringstream ss;
        for (const auto& path : paths) {
            int idx = static_cast<int>(backup_paths.size());
            backup_paths.push_back(path);
            path_health[idx] = 1.0;

            if (!path.empty()) {
                if (!ss.str().empty()) ss << "-";
                // Python: p.hex()[:4] -> first 2 bytes in hex
                std::stringstream path_ss;
                for (size_t i = 0; i < std::min<size_t>(path.size(), 2); ++i) {
                    path_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(path[i]);
                }
                ss << path_ss.str();
            }
        }

        std::string log_msg = ss.str();
        if (!log_msg.empty()) {
            pqvpn::logging::Logger::info("Added backup path: {}", log_msg);
        }
    }

    /**
     * @brief Get the currently active path.
     * Corresponds to GeographicFailover.get_active_path in main.py.
     */
    std::optional<std::vector<uint8_t>> get_active_path() const {
        if (current_path_idx == 0) {
            return primary_path;
        }
        int idx = current_path_idx - 1;
        if (static_cast<size_t>(idx) < backup_paths.size()) {
            return backup_paths[idx];
        }
        return std::nullopt;
    }

    // Accessors for testing
    const std::optional<std::vector<uint8_t>>& get_primary_path() const { return primary_path; }
    const std::vector<std::vector<uint8_t>>& get_backup_paths() const { return backup_paths; }
    const std::map<int, double>& get_path_health() const { return path_health; }
    int get_current_path_idx() const { return current_path_idx; }
    double get_last_failover() const { return last_failover; }

    void set_primary_path(const std::vector<uint8_t>& path) { primary_path = path; }
    void set_current_path(int idx) { current_path_idx = idx; } // Renamed for clarity, but tests use set_current_path_idx. Let's keep it compatible or update test.
    // Actually, the error in test was: 'class GeographicFailover' has no member named 'set_current_path_idx'
    // Wait, looking at my previous patch attempt, I had `set_current_path_idx`.
    // Let me check the existing class definition from read_file.
    // It HAD: void set_current_path_idx(int idx) { current_path_idx = idx; }
    // Why did it fail? Ah, I see in my last patch attempt:
    // "void set_current_path_idx(int idx) { current_path_idx = idx; }" was replaced by something else.

    void set_current_path_idx(int idx) { current_path_idx = idx; }
    void set_last_failover(double timestamp) { last_failover = timestamp; }

private:
    std::optional<std::vector<uint8_t>> primary_path;
    std::vector<std::vector<uint8_t>> backup_paths;
    std::map<int, double> path_health;
    int current_path_idx;
    double last_failover;
};

#endif // GEOGRAPHIC_FAILOVER_HPP
