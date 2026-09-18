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
#include <functional>
#include <algorithm>
#include <cctype>
#include <span>
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
    using TunnelPacketHandler = std::function<void(std::vector<uint8_t>)>;
    // (address, add) notification for full-tunnel route exclusions: the
    // platform layer pins each known peer address to the physical gateway so
    // tunnel transport traffic is not captured by the VPN default route. The
    // hook reports whether the requested state change succeeded; a failed ADD
    // while the TAP default is active would loop that peer's transport through
    // the adapter, so registration and session establishment fail closed on it
    // (see register_peer_from_hello / establish_hybrid_session). Removals are
    // best-effort: teardown must not be blocked by cleanup failures.
    using PeerRouteHook = std::function<bool(const asio::ip::udp::endpoint&, bool)>;
    // Frame types (main.py FT_* constants).
    static inline constexpr uint8_t HELLO_FRAME = 0;     // FT_HELLO
    static inline constexpr uint8_t S1_FRAME = 1;        // FT_S1
    static inline constexpr uint8_t S2_FRAME = 2;        // FT_S2
    static inline constexpr uint8_t DATA_FRAME = 3;      // FT_DATA
    static inline constexpr uint8_t TUNNEL_DATA_FRAME = 5;
    static inline constexpr uint8_t RELAY_FRAME = 7;     // FT_RELAY
    // Tunnel liveness (post-migration addition, ROADMAP peer selection):
    // same AEAD layout as TUNNEL_DATA_FRAME with an empty plaintext, so the
    // frame is header(16) + nonce(12) + tag(16). The type byte sits inside
    // the AAD-protected header, so it cannot be forged or confused.
    static inline constexpr uint8_t TUNNEL_PING = 6;
    static inline constexpr uint8_t TUNNEL_PONG = 8;
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
        // Hybrid-handshake keys (X25519 long-term + ML-KEM-1024) learned from
        // the peer's signed HELLO; required to initiate/complete a session.
        std::vector<uint8_t> x25519_pk{};
        std::vector<uint8_t> ml_kem_pk{};
        std::string kyber_alg{};
        std::string sig_alg{};
        double last_seen = 0.0;
    };

    // Protocol defaults (seconds). These are the built-in values a node runs
    // with when the deployment does not override them via config "tuning";
    // tests may still reference them as compile-time constants.
    static inline constexpr double SESSION_TIMEOUT = 3600.0; // 1 hour
    static inline constexpr double KEEPALIVE_INTERVAL = 30.0; // 30 seconds
    // A peer that has not answered a tunnel PING within this window is treated
    // as silent and excluded from adapter-traffic selection (fail closed).
    // Three keepalive intervals tolerate one missed round trip under load.
    static inline constexpr double LIVENESS_WINDOW = 3.0 * KEEPALIVE_INTERVAL;
    // An in-flight handshake whose S2 never arrives is pruned after this
    // horizon; the bootstrap loop re-drives contact for such peers.
    static inline constexpr double HANDSHAKE_TIMEOUT = 30.0;
    // Seconds between bootstrap contact rounds while a peer has no session yet.
    static inline constexpr double BOOTSTRAP_RETRY_INTERVAL = 10.0;

    // Per-deployment runtime tuning (seconds / counts). Initialized to the
    // protocol defaults above; main.cpp applies config "tuning" overrides on
    // top, so a deployment can retune these without recompiling.
    double session_timeout = SESSION_TIMEOUT;
    double keepalive_interval = KEEPALIVE_INTERVAL;
    double liveness_window = LIVENESS_WINDOW;
    double handshake_timeout = HANDSHAKE_TIMEOUT;
    double bootstrap_retry_interval = BOOTSTRAP_RETRY_INTERVAL;
    // Default nonce replay window applied to newly established sessions.
    size_t replay_window_size = 1024;

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
        // Replay state is split into two independent domains. The sender draws
        // BOTH from the one monotonic nonce_send counter, so nonces stay unique
        // per session key; the receiver must not let a higher counter accepted
        // in one domain evict a lower fresh counter in the other — an onion
        // layer is always peeled BEFORE the tunnel data frame it carries, and
        // both ride on the same source-destination session. The two domains are
        // also AEAD-separated (outer-header AAD vs five-part relay AAD), so a
        // captured frame cannot be replayed across domains.
        struct NonceDomain {
            uint64_t high_water = 0;   // highest counter accepted in this domain
            std::set<uint64_t> window; // bounded set of recently accepted counters
        };
        NonceDomain data_domain;  // direct tunnel frames: TUNNEL_DATA + PING/PONG
        NonceDomain relay_domain; // onion RELAY layers peeled by this node
        size_t replay_window_size = 1024;
        std::vector<uint8_t> session_iv; // 12 bytes for AES-GCM
        std::vector<uint8_t> aead_send_key;
        std::vector<uint8_t> aead_recv_key;
        SessionState state = SessionState::INITIALIZING;
        // Last time this session saw authenticated INBOUND traffic from its
        // peer (tunnel data, relay peel, or PONG). Outbound sends never
        // refresh it — a UDP handoff proves nothing about the peer — so a
        // silent session stays prunable after SESSION_TIMEOUT instead of being
        // kept alive by our own probes.
        double last_activity = 0.0;
        // Last time this peer proved liveness with an authenticated frame
        // (tunnel data, relay peel, or PONG). Refreshed by tunnel PING/PONG
        // exchanges; used to exclude silent peers from adapter traffic.
        double last_peer_response = 0.0;
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
    // Derives this node's stable identity from its ed25519 public key (my_id =
    // SHA256(ed25519 pk)); main.py uses the brainpoolP512r1 key instead. Returns
    // true and sets my_id_ when an ed25519 key is present; false otherwise.
    // Idempotent: an already-set identity is kept, so explicit set_my_id callers are unaffected.
    bool establish_identity();
    void set_tofu_enabled(const bool enabled) { tofu_enabled_ = enabled; }
    void set_allowlist(std::set<std::string> allowlist) { allowlist_ = std::move(allowlist); }
    void add_known_peer(const std::vector<uint8_t>& peer_id);
    std::vector<uint8_t> session_salt(const std::vector<uint8_t>& peer_id) const;
    bool is_peer_allowed(const std::vector<uint8_t>& peer_id) const;
    bool check_and_record_nonce(Session& session, Session::NonceDomain& domain,
                                const std::vector<uint8_t>& nonce) const;
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
    void set_tunnel_packet_handler(TunnelPacketHandler handler) {
        tunnel_packet_handler_ = std::move(handler);
    }

    // Installs the peer-route exclusion hook (see PeerRouteHook). Called with
    // add=true when a peer address becomes known (HELLO registration, session
    // establishment) and add=false when its session is pruned. A failed ADD is
    // fail-closed at those admission points; removals stay best-effort.
    void set_peer_route_hook(PeerRouteHook hook) { peer_route_hook_ = std::move(hook); }
    // Reports whether the requested route state change succeeded (true when no
    // hook is installed: full-tunnel routing is not active and there is nothing
    // to gate on). A throwing hook counts as a failed change.
    bool notify_peer_route(const asio::ip::udp::endpoint& address, bool add);
    std::optional<std::vector<uint8_t>> build_tunnel_datagram(
        const std::vector<uint8_t>& peer_id,
        std::span<const uint8_t> packet);

    // Builds one authenticated liveness frame (TUNNEL_PING or TUNNEL_PONG):
    // header(16) + nonce(12) + tag(16), empty plaintext, AAD = the 16-byte
    // header. Fails closed when the session cannot carry it.
    std::optional<std::vector<uint8_t>> build_tunnel_liveness_frame(
        uint8_t frame_type,
        Session& session);
    bool send_tunnel_packet(
        const std::vector<uint8_t>& peer_id,
        std::span<const uint8_t> packet);

    // Automatic peer selection for adapter-originated traffic (TAP data path):
    // among ESTABLISHED sessions with a routable remote address, only peers
    // that answered within LIVENESS_WINDOW are eligible; the most recently
    // active of those carries the packet. Ties resolve to the lexicographically
    // smallest peer id so the choice is deterministic. Returns nullopt when no
    // live peer exists: adapter traffic then fails closed instead of being
    // sent into a black hole.
    std::optional<std::vector<uint8_t>> select_tunnel_peer() const;

    // Sends one tunnel PING to an established peer and returns whether it was
    // posted for delivery. The peer replies with a TUNNEL_PONG, which refreshes
    // last_peer_response on both sides (see datagram_received).
    asio::awaitable<bool> ping_tunnel_peer(const std::vector<uint8_t>& peer_id);

    // Forwards one adapter-originated packet through the selected tunnel
    // session. Runs on the io_context with a posted send, so it is safe to
    // invoke from the adapter reader thread (see post_udp_send). Returns false
    // when no established session can carry the packet.
    asio::awaitable<bool> forward_adapter_packet(std::vector<uint8_t> packet);

    const std::string& config_path() const { return config_path_; }

    std::string my_id_str;
    std::optional<std::vector<uint8_t>> my_id_;
    std::vector<uint8_t> ed25519_public_key;
    std::vector<uint8_t> brainpool_public_key;
    std::vector<uint8_t> ml_kem_public_key;
    std::vector<uint8_t> ml_dsa_public_key;
    // Private halves of the node identity (see node_identity.hpp). Public
    // counterparts are mirrored into the *_public_key fields above.
    std::vector<uint8_t> ed25519_private_key;
    std::vector<uint8_t> x25519_public_key;
    std::vector<uint8_t> x25519_private_key;
    std::vector<uint8_t> ml_kem_secret_key;
    std::vector<uint8_t> ml_dsa_private_key;
    // Loads the persistent identity from <config dir>/node_keys.json, or
    // generates and stores one when absent. Returns false (and leaves all key
    // material empty) only when neither load nor generation succeeds.
    bool load_or_create_identity();
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
    // Resolves a peer's advertised hybrid keys (x25519 long-term + ML-KEM)
    // from the mesh registration or the known-peers store. Returns nullopt
    // when either key is missing — handshakes with such peers fail closed.
    std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> peer_hybrid_keys(
        const std::vector<uint8_t>& peer_id) const;
    // Releases the peer-route exclusion for `address` only when no live consumer can
    // still send to that exact endpoint — neither another session nor a relay-capable
    // mesh entry uses it. Keeps the exclusion while any such consumer remains, so pruning
    // one stale session cannot leave an active relay path looping through the TAP default
    // (see maintenance_tick). Endpoints on a shared /32 are independent references in
    // PeerRouteManager, so releasing this one preserves the OS route for the others. Any
    // future code path that removes a mesh peer must call this instead of
    // notify_peer_route(..., false) directly.
    void release_peer_route_if_unreferenced(const asio::ip::udp::endpoint& address);
    // One pass of session upkeep (prune stale, rekey due, probe liveness),
    // split from the timer loop so tests can drive it directly. Never holds a
    // sessions_by_peer_id iterator or reference across a suspension.
    asio::awaitable<void> maintenance_tick();
    asio::awaitable<void> session_maintenance();
    asio::awaitable<void> datagram_received(std::vector<uint8_t> data, asio::ip::udp::endpoint endpoint);
    std::optional<std::map<std::string, std::string>> find_known_peer_by_pubkeys(const std::map<std::string, std::string>& j);
    std::optional<PeerInfo> register_peer_from_hello(const std::map<std::string, std::string>& hello, const asio::ip::udp::endpoint& address);
    bool register_peer_tofu(const std::vector<uint8_t>& peer_id, const std::map<std::string, std::string>& info);
    std::optional<std::vector<uint8_t>> choose_relay(const std::vector<uint8_t>& dest_peer_id);
    asio::awaitable<bool> send_onion(const std::vector<std::vector<uint8_t>>& path, const std::vector<uint8_t>& inner_frame);

    // Decrypts one onion RELAY layer and either forwards the peeled content to
    // the next hop or delivers it locally. Wire format per layer (main.py):
    //   outer frame [1][RELAY_FRAME][next_hash(8)][circuit_id(4 BE)][len(2 BE)]
    //   payload     = session_hint(8) + nonce(12) + ciphertext+tag
    // The AEAD AAD is "PQVPN" + full session id + the 8-byte identity hash of
    // the node that peels this layer + circuit_id (4 BE).
    // `sender` must be the peer the resolved session was established with:
    // like the direct tunnel path, relay layers are bound to their origin so
    // stolen session material cannot be injected from an unregistered address.
    asio::awaitable<bool> handle_relay(
        const std::vector<uint8_t>& session_hint,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& ciphertext_and_tag,
        const std::vector<uint8_t>& outer_next_hash,
        uint32_t circuit_id,
        const asio::ip::udp::endpoint& sender);

    // New Gossip Update Handler
    void handle_gossip_update(const std::vector<uint8_t>& peer_id, const std::string& nickname, bool is_relay);

    // Handlers from UDPProtocol
    asio::awaitable<void> handle_hello(std::vector<uint8_t> payload, const std::map<std::string, std::string>& extra_info, const std::vector<uint8_t>& signature, uint64_t nonce);
    asio::awaitable<void> handle_gossip(std::vector<uint8_t> payload, asio::ip::udp::endpoint endpoint);

    // ---- Hybrid handshake control plane (HELLO / S1 / S2) -----------------
    // Wire contract (both sides are this implementation; the field set mirrors
    // main.py's HELLO/S1 with X25519 + ML-KEM-1024 in place of BrainpoolP/Kyber):
    //   HELLO  {peerid, nickname, ed25519_pk, x25519_pk, ml_kem_pk, mldsa_pk,
    //           timestamp, response, sessionid} + ed25519_sig + mldsa_sig
    //   S1     {peerid, sessionid, ct, x25519_pk(ephemeral), ed25519_pk,
    //           mldsa_pk, timestamp} + both signatures
    //   S2     {peerid, sessionid, ed25519_pk, mldsa_pk, timestamp}
    //           + both signatures
    // Signatures cover the canonical JSON of exactly those fields (fixed order,
    // signatures excluded). Both Ed25519 AND ML-DSA must verify — partial
    // authentication is rejected. Key material:
    //   x25519_secret = X25519(ephemeral_sk, peer_longterm_pk) / (peer_ephemeral_pk, longterm_sk)
    //   ml_kem_secret = ML-KEM-1024 encaps/decaps shared secret
    //   transcript    = the raw S1 payload bytes as sent by the initiator
    //   keys          = establish_hybrid_session(...) over those three inputs.
    asio::awaitable<void> handle_hello_frame(std::vector<uint8_t> payload, const asio::ip::udp::endpoint& endpoint);
    asio::awaitable<void> handle_s1_frame(std::vector<uint8_t> payload, const asio::ip::udp::endpoint& endpoint);
    asio::awaitable<void> handle_s2_frame(std::vector<uint8_t> payload, const asio::ip::udp::endpoint& endpoint);

    // Initiates the handshake toward a registered peer: ephemeral X25519 +
    // ML-KEM encapsulation against the peer's advertised keys, signed S1 sent,
    // pending state kept until S2 arrives. Returns false when the peer cannot
    // be contacted (missing keys, no transport) — fail closed.
    bool initiate_handshake(const std::vector<uint8_t>& peer_id, const asio::ip::udp::endpoint& endpoint);

    // Startup contact loop: for every configured bootstrap address that has no
    // established session yet, send a signed HELLO (response=false). Repeats on
    // an interval until the session exists; silent once it does. The list is
    // taken BY VALUE because the coroutine outlives any caller's temporaries.
    asio::awaitable<void> bootstrap_peers(std::vector<asio::ip::udp::endpoint> peers);

    // One pending initiator-side handshake, keyed by session id hex in
    // pending_handshakes_. The transcript is the exact S1 payload bytes so the
    // responder (which signs/derives from what it received) derives identical
    // keys.
    struct PendingHandshake {
        std::vector<uint8_t> peer_id;
        asio::ip::udp::endpoint endpoint;
        std::vector<uint8_t> x25519_ephemeral_sk;
        std::vector<uint8_t> ml_kem_secret;
        std::vector<uint8_t> transcript;
        double created_at = 0.0;
    };

private:
    std::string config_path_;
    TunnelPacketHandler tunnel_packet_handler_;
    PeerRouteHook peer_route_hook_;
    std::unordered_map<std::string, PendingHandshake> pending_handshakes_;
};

} // namespace pqvpn
#endif
