#ifndef TOPOLOGY_MODULE_HPP
#define TOPOLOGY_MODULE_HPP

#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <string>
#include <cstdint>
#include <algorithm>

/**
 * @brief Peer metadata used by MeshTopology.
 */
struct PeerInfo {
    std::vector<uint8_t> peer_id;
    std::string nickname;
    double latency_ms = 0.0;
    double route_quality = 1.0;
};

/**
 * @brief Mesh Network Topology Manager.
 * Corresponds to MeshTopology in main.py.
 */
class MeshTopology {
public:
    /**
     * @brief Initializes the mesh topology with empty peers, routes, and adjacency lists.
     * Corresponds to MeshTopology.__init__ in main.py.
     */
    MeshTopology()
        : last_update(get_current_time())
    {}

    /**
     * @brief Adds a peer to the topology.
     * Corresponds to MeshTopology.add_peer in main.py.
     * @param peer_info The information about the peer being added.
     */
    void add_peer(const PeerInfo& peer_info) {
        peers[peer_info.peer_id] = peer_info;
        adjacency[peer_info.peer_id] = std::set<std::vector<uint8_t>>{};
    }

    /**
     * @brief Updates quality metrics for an existing peer.
     * Corresponds to MeshTopology.update_peer_quality in main.py.
     * @param peer_id The ID of the peer to update.
     * @param latency_ms The new latency in milliseconds.
     * @param packet_loss The new packet loss percentage (0-100).
     */
    void update_peer_quality(const std::vector<uint8_t>& peer_id, double latency_ms, double packet_loss) {
        auto it = peers.find(peer_id);
        if (it != peers.end()) {
            it->second.latency_ms = latency_ms;
            it->second.route_quality = std::max(0.1, 1.0 - (packet_loss / 100.0));
        }
    }

    /**
     * @brief Computes the best path between two peers.
     * Corresponds to MeshTopology.compute_best_path in main.py.
     * @param source The source peer ID.
     * @param destination The destination peer ID.
     * @return A vector of peer IDs representing the path, or an empty vector if no path exists.
     */
    std::vector<std::vector<uint8_t>> compute_best_path(const std::vector<uint8_t>& source, const std::vector<uint8_t>& destination) {
        if (peers.find(destination) == peers.end() || peers.find(source) == peers.end()) {
            return {};
        }
        return {source, destination};
    }

    // Accessors for testing purposes
    const std::map<std::vector<uint8_t>, PeerInfo>& get_peers() const { return peers; }
    double get_last_update() const { return last_update; }

private:
    std::map<std::vector<uint8_t>, PeerInfo> peers;
    std::map<std::vector<uint8_t>, std::vector<std::vector<uint8_t>>> routes;
    std::map<std::vector<uint8_t>, std::set<std::vector<uint8_t>>> adjacency;
    double last_update;

    static double get_current_time() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration<double>(duration).count();
    }
};

#endif // TOPOLOGY_MODULE_HPP
