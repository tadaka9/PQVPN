#ifndef PQVPN_NODE_H
#define PQVPN_NODE_H

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <optional>

// Forward declaration of transport classes
class Transport {
public:
    virtual ~Transport() = default;
    virtual void sendto(const std::vector<uint8_t>& data, const std::string& host, int port) = 0;
};

class IPv4Transport {
public:
    virtual ~IPv4Transport() = default;
    virtual void sendto(const std::vector<uint8_t>& data, const std::string& host, int port) = 0;
};

class PQVPNNode : public std::enable_shared_from_this<PQVPNNode> {
public:
    // ... existing methods ...
    void add_to_cache(const std::string& peer_id, const PeerInfo& pinfo);
    std::optional<PeerInfo> get_from_cache(const std::string& peer_id);
    void gossip_peer(const PeerInfo& pinfo);

private:
    // ... existing members ...
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, PeerInfo> recent_peers_cache_;
};
    std::string nickname;
    std::vector<uint8_t> ed25519_pk;
    std::vector<uint8_t> brainpoolP512r1_pk;
    std::vector<uint8_t> kyber_pk;
    std::vector<uint8_t> mldsa_pk;
};

// Forward declaration for SessionInfo
struct SessionInfo {
    std::vector<uint8_t> session_id;
    std::vector<uint8_t> peer_id;
    std::vector<uint8_t> send_key;
    std::vector<uint8_t> recv_key;
    int state;
    std::string remote_addr;
};

enum SESSION_STATE {
    SESSION_STATE_ESTABLISHED = 1
};

class PQVPNNode : public std::enable_shared_from_this<PQVPNNode> {
public:
    PQVPNNode(boost::asio::io_context& io_context, const std::string& config_path);

    void set_port(int new_port);
    int get_port() const { return port; }

    boost::asio::io_context& get_io_context() { return io_context_; }
    bool send_to(const std::vector<uint8_t>& data, const std::string& host, int port_num);

    void initiate_handshake(const PeerInfo& pinfo, const std::string& addr, int port);
    void handle_s1(const std::vector<uint8_t>& payload, const std::string& addr, int port,
                   const std::vector<uint8_t>& outer_next_hash = {}, int circuit_id = 0);
    void handle_hello(const std::vector<uint8_t>& payload, const std::string& addr, int port,
                      const std::vector<uint8_t>& outer_next_hash = {}, int circuit_id = 0);
    void handle_s2(const std::vector<uint8_t>& payload, const std::string& addr,
                   const std::vector<uint8_t>& outer_next_hash = {}, int circuit_id = 0);

    void load_keys();

    // L1 Cache Management (Hybrid Approach)
    void add_to_cache(const std::string& peer_id, const PeerInfo& pinfo);
    std::optional<PeerInfo> get_from_cache(const std::string& peer_id);
    void gossip_peer(const PeerInfo& pinfo);

private:
    boost::asio::io_context& io_context_;
    boost::asio::steady_timer telemetry_timer_;
    std::string config_path_;
    std::shared_ptr<Transport> transport;
    std::shared_ptr<IPv4Transport> ipv4_transport;
    std::vector<uint8_t> session_id;
    int port;

    // L1 Cache Data
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, PeerInfo> recent_peers_cache_;

    struct sockaddr* get_sockaddr(const std::string& host, int port_num, bool is_ipv4);
    int get_sockaddr_len(bool is_ipv4);
    std::vector<uint8_t> pq_kem_encaps(const std::vector<uint8_t>& kyber_pk);
    std::string make_outer_frame(int ft_type, const std::vector<uint8_t>& session_id, uint32_t circuit_id, const std::vector<uint8_t>& data);

    void broadcast_telemetry();
    void schedule_telemetry();
    void set_test_mode(bool test);
    bool is_test_mode() const;
};

#endif // PQVPN_NODE_H
