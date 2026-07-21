#ifndef PQVPN_NODE_MODULE_HPP
#define PQVPN_NODE_MODULE_HPP

#include <string>
#include <memory>
#include <stdexcept>
#include <vector>
#include <semaphore>
#include <expected>
#include <asio.hpp>
#include <set>
#include <sstream>
#include <iomanip>
#include <optional>
#include <unordered_map>
#include <map>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <openssl/sha.h>
#include "udp_protocol.hpp"
#include "rekey_manager.hpp"
#include <chrono>
#include <cstdint>

namespace pqvpn {

class PluginManager;

/**
 * @brief Minimal discovery lifecycle interface used by the runtime.
 */
class DiscoveryStub {
public:
    asio::awaitable<void> start() {
        co_return;
    }
    asio::awaitable<void> stop() {
        co_return;
    }
};

/**
 * @brief ASIO-backed PQVPN node state and protocol interface.
 */
class PQVPNNode : public std::enable_shared_from_this<PQVPNNode> {
public:
    struct PeerInfo {
        std::vector<uint8_t> peer_id;
        bool is_relay = false;
        asio::ip::udp::endpoint address;
        std::string nickname;

        // Public keys and metadata learned from HELLO registration.
        std::vector<uint8_t> ed25519_pk{};
        std::vector<uint8_t> brainpoolP512r1_pk{};
        std::vector<uint8_t> kyber_pk{};
        std::vector<uint8_t> mldsa_pk{};
        std::string kyber_alg{};
        std::string sig_alg{};
        double last_seen = 0.0;
    };

    static inline constexpr double SESSION_TIMEOUT = 3600.0; // 1 hour
    static inline constexpr double KEEPALIVE_INTERVAL = 30.0; // 30 seconds

    enum class SessionState {
        INITIALIZING,
        HANDSHAKING,
        ESTABLISHED,
        CLOSING,
        CLOSED
    };

    struct Session {
        std::vector<uint8_t> session_id;
        std::optional<std::vector<uint8_t>> peer_id_;
        asio::ip::udp::endpoint remote_addr;
        uint64_t nonce_send = 0;
        uint64_t nonce_recv = 0;
        std::set<uint64_t> replay_window;
        size_t replay_window_size = 1024;
        std::vector<uint8_t> session_iv; // 12 bytes for AES-GCM
        std::vector<uint8_t> aead_send_key;
        std::vector<uint8_t> aead_recv_key;
        SessionState state = SessionState::INITIALIZING;
        double last_activity = 0.0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_recv = 0;
        double created_at = 0.0;
    };

    struct MeshTopology {
        std::unordered_map<std::string, PeerInfo> peers;

        const PeerInfo* get_peer(const std::vector<uint8_t>& pid) const {
            std::stringstream ss;
            for (auto b : pid) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
            auto it = peers.find(ss.str());
            return (it != peers.end()) ? &it->second : nullptr;
        }

        const std::unordered_map<std::string, PeerInfo>& all_peers() const {
            return peers;
        }
    } mesh;

    explicit PQVPNNode(asio::io_context& io_context, const std::string& config_path)
        : config_path_(config_path), io_context_(io_context)
    {}

    explicit PQVPNNode(asio::io_context& io_context)
        : config_path_("config.json"), io_context_(io_context) {}

    explicit PQVPNNode(const std::string& config_path)
        : owned_io_context_(std::make_shared<asio::io_context>()),
          config_path_(config_path), io_context_(*owned_io_context_) {}

    asio::io_context& get_io_context() { return io_context_; }
    const asio::io_context& get_io_context() const { return io_context_; }
    void set_my_id(std::vector<uint8_t> identity) { my_id_ = std::move(identity); }
    void set_tofu_enabled(const bool enabled) { tofu_enabled_ = enabled; }
    void set_allowlist(std::set<std::string> allowlist) { allowlist_ = std::move(allowlist); }
    void add_known_peer(const std::vector<uint8_t>& peer_id);
    std::vector<uint8_t> session_salt(const std::vector<uint8_t>& peer_id) const;
    bool is_peer_allowed(const std::vector<uint8_t>& peer_id) const;
    bool check_and_record_nonce(Session& session, const std::vector<uint8_t>& nonce) const;
    std::vector<uint8_t> make_outer_frame(uint8_t frame_type, const std::vector<uint8_t>& hop_id,
                                          uint32_t circuit_id, const std::vector<uint8_t>& payload) const;
    std::vector<uint8_t> peer_hash8(const std::vector<uint8_t>& peer_id) const {
        std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
        SHA256(peer_id.data(), peer_id.size(), digest.data());
        digest.resize(8);
        return digest;
    }
    std::optional<std::vector<uint8_t>> build_onion_frame(
        const std::vector<std::vector<uint8_t>>& path, const std::vector<uint8_t>& inner_frame);
    std::optional<std::vector<uint8_t>> build_onion_frame_with_circuit(
        const std::vector<std::vector<uint8_t>>& path, const std::vector<uint8_t>& inner_frame,
        uint32_t circuit_id);
    std::shared_ptr<Session> establish_hybrid_session(
        const std::vector<uint8_t>& peer_id,
        const asio::ip::udp::endpoint& remote_endpoint,
        const std::vector<uint8_t>& x25519_secret,
        const std::vector<uint8_t>& ml_kem_secret,
        const std::vector<uint8_t>& handshake_transcript,
        bool initiator);

    const std::string& config_path() const { return config_path_; }

    std::string my_id_str;
    std::optional<std::vector<uint8_t>> my_id_;
    std::vector<uint8_t> ed25519_public_key;
    std::vector<uint8_t> brainpool_public_key;
    std::vector<uint8_t> ml_kem_public_key;
    std::vector<uint8_t> ml_dsa_public_key;
    std::string known_peers_file_ = "known_peers.yaml";

    std::shared_ptr<asio::io_context> owned_io_context_;
    asio::io_context& io_context_;

    asio::ip::udp::socket* transport = nullptr;
    asio::ip::udp::socket* ipv4_transport = nullptr;

    struct VectorHasher {
        size_t operator()(const std::vector<uint8_t>& v) const {
            size_t seed = v.size();
            for(auto x : v) {
                seed ^= static_cast<size_t>(x)
                      + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            }
            return seed;
        }
    };

    std::unordered_map<std::vector<uint8_t>, std::shared_ptr<Session>, VectorHasher> sessions_by_peer_id;
    RekeyManager rekey_manager;
    std::unordered_map<std::string, std::map<std::string, std::string>> known_peers_;
    bool strict_tofu_ = false;
    bool tofu_enabled_ = true;
    std::set<std::string> allowlist_;

    void save_known_peers();
    void load_known_peers();
    asio::awaitable<void> session_maintenance();
    asio::awaitable<void> datagram_received(std::vector<uint8_t> data, asio::ip::udp::endpoint endpoint);
    std::optional<std::map<std::string, std::string>> find_known_peer_by_pubkeys(const std::map<std::string, std::string>& j);
    std::optional<PeerInfo> register_peer_from_hello(const std::map<std::string, std::string>& hello, const asio::ip::udp::endpoint& address);
    bool register_peer_tofu(const std::vector<uint8_t>& peer_id, const std::map<std::string, std::string>& info);
    std::optional<std::vector<uint8_t>> choose_relay(const std::vector<uint8_t>& dest_peer_id);
    asio::awaitable<bool> send_onion(const std::vector<std::vector<uint8_t>>& path, const std::vector<uint8_t>& inner_frame);

    // New Gossip Update Handler
    void handle_gossip_update(const std::vector<uint8_t>& peer_id, const std::string& nickname, bool is_relay);

    // Handlers from UDPProtocol
    asio::awaitable<void> handle_hello(std::vector<uint8_t> payload, const std::map<std::string, std::string>& extra_info, const std::vector<uint8_t>& signature, uint64_t nonce);
    asio::awaitable<void> handle_gossip(std::vector<uint8_t> payload, asio::ip::udp::endpoint endpoint);

private:
    std::string config_path_;
};

} // namespace pqvpn
#endif
