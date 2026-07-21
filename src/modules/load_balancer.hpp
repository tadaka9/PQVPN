#ifndef PQVPN_LOAD_BALANCER_HPP
#define PQVPN_LOAD_BALANCER_HPP

#include <map>
#include <string>
#include <vector>
#include <tuple>
#include <unordered_map>
#include <stdexcept>
#include <optional>
#include <spdlog/spdlog.h>
#include <cstdint>

namespace pqvpn {

/**
 * @brief Constant for default packets per second limit.
 */
inline constexpr int DEFAULT_PPS_LIMIT = 1000;

/**
 * @brief Forward declarations for dependencies.
 */
enum class SessionState {
    INITIALIZING,
    HANDSHAKING,
    ESTABLISHED,
    CLOSING,
    CLOSED
};

// Mapping the Python string constant to our C++ enum.
inline constexpr SessionState SESSION_STATE_ESTABLISHED = SessionState::ESTABLISHED;

struct SessionInfo {
    SessionState state;
    uint64_t bytes_sent;
};

using Bytes = std::vector<uint8_t>;

/**
 * @brief Distributed Load Balancing and Traffic Shaping.
 *
 * Ported from main.py: LoadBalancer.__init__ (main.py:1644-1647)
 */
class LoadBalancer {
public:
    /**
     * @brief Initialize the load balancer with default structures.
     *
     * Corresponds to Python's __init__:
     * - self.flow_affinity: Dict[Tuple[str, str, int], bytes] = {}
     * - self.token_buckets: Dict[bytes, Tuple[float, float]] = {}
     * - self.rate_limits: Dict[bytes, int] = defaultdict(lambda: DEFAULT_PPS_LIMIT)
     */
    LoadBalancer() : flow_affinity(), token_buckets(), rate_limits() {
        // In C++, containers are default-initialized to empty.
    }

    /**
     * @brief Selects session for flow with load balancing logic.
     *
     * Ported from main.py: LoadBalancer.select_session (main.py:1649-1666)
     */
    template<typename Hasher>
    std::optional<Bytes> select_session(const std::unordered_map<Bytes, SessionInfo, Hasher>& sessions) {
        if (sessions.empty()) {
            return std::nullopt;
        }

        Bytes best_session_id;
        double best_score = -1.0;

        for (const auto& [session_id, sess] : sessions) {
            if (sess.state != SESSION_STATE_ESTABLISHED) {
                continue;
            }

            // score = 1.0 - (sess.bytes_sent / 1000.0)
            double score = 1.0 - (static_cast<double>(sess.bytes_sent) / 1000.0);
            if (score > best_score) {
                best_score = score;
                best_session_id = session_id;
            }
        }

        if (best_score <= -1.0) {
            return std::nullopt;
        }

        return best_session_id;
    }

    /**
     * @brief Helper to mimic defaultdict behavior for rate_limits
     */
    int get_rate_limit(const Bytes& peer_id) const {
        auto it = rate_limits.find(peer_id);
        if (it == rate_limits.end()) {
            return DEFAULT_PPS_LIMIT;
        }
        return it->second;
    }

    void set_rate_limit(const Bytes& peer_id, int limit) {
        if (!peer_id.empty()) {
            spdlog::info("Setting rate limit for peer {:X} to {}", peer_id[0], limit);
        }
        rate_limits[peer_id] = limit;
    }

private:
    // Key: Tuple[str, str, int] -> Using a concatenated string for simplicity in this port
    std::map<std::string, Bytes> flow_affinity;

    // Key: bytes (vector<uint8_t>)
    struct BytesHasher {
        std::size_t operator()(const Bytes& v) const {
            std::size_t seed = 0;
            for(auto x : v) {
                seed ^= std::hash<uint8_t>{}(x)
                     + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            }
            return seed;
        }
    };

    // Key: bytes (vector<uint8_t>)
    std::unordered_map<Bytes, std::pair<double, double>, BytesHasher> token_buckets;

    // Key: bytes (vector<uint8_t>)
    std::unordered_map<Bytes, int, BytesHasher> rate_limits;
};

} // namespace pqvpn

#endif // PQVPN_LOAD_BALANCER_HPP
