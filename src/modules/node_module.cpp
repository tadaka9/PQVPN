#include "node_module.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <limits>
#include <optional>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <vector>
#include <nlohmann/json.hpp>
#include <random>
#include "crypto_utils.hpp"
#include "hybrid_auth.hpp"
#include "hybrid_kdf.hpp"
#include "node_identity.hpp"
#include "tunnel_aead.hpp"

using namespace pqvpn;
using namespace std::chrono_literals;

namespace {

// Invokes the tunnel packet sink while isolating its failures: a throwing
// sink drops this frame only and the node keeps processing traffic. A VPN
// daemon must not terminate because its packet consumer misbehaves (for
// example when the adapter is already closed during shutdown).
void invoke_tunnel_sink(const PQVPNNode::TunnelPacketHandler& sink, const std::vector<uint8_t>& packet,
                        const std::vector<uint8_t>& src_peer_id) {
    if (!sink) return;
    try {
        sink(packet, src_peer_id);
    } catch (const std::exception& error) {
        std::cerr << "tunnel packet sink failed: " << error.what() << "\n";
    } catch (...) {
        std::cerr << "tunnel packet sink failed with an unknown exception\n";
    }
}

std::optional<std::vector<uint8_t>> decode_hex(const std::string& value) {
    if (value.empty() || value.size() % 2 != 0 ||
        !std::all_of(value.begin(), value.end(), [](const unsigned char c) { return std::isxdigit(c) != 0; })) {
        return std::nullopt;
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(value.size() / 2);
    for (std::size_t offset = 0; offset < value.size(); offset += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(value.substr(offset, 2), nullptr, 16)));
    }
    return bytes;
}

std::string normalize_public_key(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(), [](const unsigned char c) {
        return std::isspace(c) != 0;
    }), value.end());

    if (!value.empty() && value.size() % 2 == 0 &&
        std::all_of(value.begin(), value.end(), [](const unsigned char c) { return std::isxdigit(c) != 0; })) {
        std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }

    if (value.empty() || value.size() % 4 != 0) {
        return value;
    }
    std::vector<unsigned char> decoded((value.size() / 4) * 3);
    const int decoded_size = EVP_DecodeBlock(decoded.data(),
        reinterpret_cast<const unsigned char*>(value.data()), static_cast<int>(value.size()));
    if (decoded_size < 0) {
        return value;
    }
    std::size_t size = static_cast<std::size_t>(decoded_size);
    if (!value.empty() && value.back() == '=') --size;
    if (value.size() > 1 && value[value.size() - 2] == '=') --size;
    decoded.resize(size);

    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(decoded.size() * 2);
    for (const auto byte : decoded) {
        hex.push_back(digits[byte >> 4]);
        hex.push_back(digits[byte & 0x0f]);
    }
    return hex;
}

std::vector<uint8_t> peer_hash8(const std::vector<uint8_t>& id) {
    if (id.size() < 8) return id;
    return std::vector<uint8_t>(id.begin(), id.begin() + 8);
}

std::string hex_id(const std::vector<uint8_t>& id) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const auto byte : id) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

// ---- Hybrid handshake control plane helpers -------------------------------

double now_seconds() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string escape_json_string(const std::string& value) {
    static constexpr char hexdigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out.push_back(hexdigits[(c >> 4) & 0xf]);
                    out.push_back(hexdigits[c & 0xf]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

// Canonical signing bytes: exactly the listed fields present in `j`, in this
// fixed order, compact JSON. Signatures are never part of it; both sides
// recompute it from the parsed wire object, so key order on the wire is
// irrelevant and a field cannot be dropped or reordered without breaking
// verification.
std::string canonical_json(const nlohmann::json& j, const std::vector<std::string>& field_order) {
    std::string out = "{";
    bool first = true;
    for (const auto& name : field_order) {
        if (!j.contains(name)) continue;
        if (!first) out += ",";
        first = false;
        const auto& value = j.at(name);
        out += "\"" + name + "\":";
        if (value.is_string()) {
            out += "\"" + escape_json_string(value.get<std::string>()) + "\"";
        } else {
            out += value.dump(); // numbers / booleans
        }
    }
    return out + "}";
}

std::optional<std::vector<uint8_t>> hex_field(const nlohmann::json& j, const char* name) {
    if (!j.contains(name)) return std::nullopt;
    const auto& value = j.at(name);
    if (value.is_string()) return decode_hex(value.get<std::string>());
    return std::nullopt;
}

std::vector<uint8_t> random_bytes(std::size_t size) {
    static thread_local std::mt19937_64 engine{std::random_device{}()};
    std::uniform_int_distribution<unsigned> dist(0, 255);
    std::vector<uint8_t> out;
    out.reserve(size);
    for (std::size_t i = 0; i < size; ++i) out.push_back(static_cast<uint8_t>(dist(engine)));
    return out;
}

// Fixed field orders for the signed handshake messages (signatures excluded).
const std::vector<std::string> kHelloFields = {
    "peerid", "nickname", "ed25519_pk", "x25519_pk", "ml_kem_pk",
    "mldsa_pk", "timestamp", "response", "sessionid"};
const std::vector<std::string> kS1Fields = {
    "peerid", "sessionid", "ct", "x25519_pk", "ed25519_pk", "mldsa_pk", "timestamp"};
const std::vector<std::string> kS2Fields = {
    "peerid", "sessionid", "ed25519_pk", "mldsa_pk", "x25519_pk", "timestamp"};

// Strict hybrid policy: BOTH Ed25519 and ML-DSA must verify over the same
// canonical bytes. Partial authentication is rejected (README perimeter).
bool verify_hybrid_signatures(const nlohmann::json& j, const std::vector<std::string>& field_order) {
    if (!j.is_object()) return false;
    auto ed_pk = hex_field(j, "ed25519_pk");
    auto ed_sig = hex_field(j, "ed25519_sig");
    auto mld_pk = hex_field(j, "mldsa_pk");
    auto mld_sig = hex_field(j, "mldsa_sig");
    if (!ed_pk || !ed_sig || !mld_pk || !mld_sig) return false;
    const std::string canonical = canonical_json(j, field_order);
    const std::vector<uint8_t> message(canonical.begin(), canonical.end());
    bool ed_ok = false;
    bool mld_ok = false;
    try { ed_ok = crypto::ed25519_verify(*ed_pk, message, *ed_sig); } catch (...) {}
    try { mld_ok = pq_sig_verify(*mld_pk, message, *mld_sig, "ML-DSA-87"); } catch (...) {}
    return ed_ok && mld_ok;
}

// Signs `message` with the node's Ed25519 and ML-DSA keys; returns hex pairs.
std::pair<std::string, std::string> sign_hybrid_message(
    const std::vector<uint8_t>& ed25519_sk,
    const std::vector<uint8_t>& mldsa_sk,
    const std::string& message) {
    const auto ed = crypto::ed25519_sign(ed25519_sk, std::vector<uint8_t>(message.begin(), message.end()));
    const auto mld = pq_sig_sign(mldsa_sk, std::vector<uint8_t>(message.begin(), message.end()), "ML-DSA-87");
    return {hex_id(ed), hex_id(mld)};
}

// Builds this node's signed HELLO body (response flag selects direction).
nlohmann::json build_signed_hello(const PQVPNNode& node, const bool response) {
    nlohmann::json j = {
        {"peerid", node.my_id_.has_value() ? hex_id(*node.my_id_) : std::string{}},
        {"nickname", "pqvpn-node"},
        {"ed25519_pk", hex_id(node.ed25519_public_key)},
        {"x25519_pk", hex_id(node.x25519_public_key)},
        {"ml_kem_pk", hex_id(node.ml_kem_public_key)},
        {"mldsa_pk", hex_id(node.ml_dsa_public_key)},
        {"timestamp", static_cast<long long>(now_seconds())},
        {"response", response},
        {"sessionid", std::string{}}
    };
    const auto [ed_sig, mld_sig] = sign_hybrid_message(
        node.ed25519_private_key, node.ml_dsa_private_key,
        canonical_json(j, kHelloFields));
    j["ed25519_sig"] = ed_sig;
    j["mldsa_sig"] = mld_sig;
    return j;
}

std::optional<std::vector<uint8_t>> send_outer_frame(
    PQVPNNode& node,
    uint8_t frame_type,
    const std::string& wire_payload,
    const asio::ip::udp::endpoint& endpoint) {
    if (!node.transport || endpoint.address().is_unspecified()) return std::nullopt;
    auto frame = node.make_outer_frame(frame_type, std::vector<uint8_t>(8, 0), 0,
        std::vector<uint8_t>(wire_payload.begin(), wire_payload.end()));
    asio::error_code error;
    node.transport->send_to(asio::buffer(frame), endpoint, 0, error);
    if (error) {
        std::cerr << "UDP send to " << endpoint << " failed: " << error.message() << "\n";
        return std::nullopt;
    }
    return frame;
}

std::vector<uint8_t> encode_outer_frame(
    const uint8_t frame_type,
    const std::vector<uint8_t>& hop_id,
    const uint32_t circuit_id,
    const std::vector<uint8_t>& payload) {
    if (payload.size() > UINT16_MAX) {
        throw std::length_error("outer frame payload exceeds 65535 bytes");
    }

    std::vector<uint8_t> frame{1, frame_type};
    frame.resize(10, 0);
    std::copy_n(hop_id.begin(), std::min<std::size_t>(hop_id.size(), 8), frame.begin() + 2);
    frame.push_back(static_cast<uint8_t>((circuit_id >> 24) & 0xff));
    frame.push_back(static_cast<uint8_t>((circuit_id >> 16) & 0xff));
    frame.push_back(static_cast<uint8_t>((circuit_id >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(circuit_id & 0xff));
    const auto payload_size = static_cast<uint16_t>(payload.size());
    frame.push_back(static_cast<uint8_t>((payload_size >> 8) & 0xff));
    frame.push_back(static_cast<uint8_t>(payload_size & 0xff));
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

// tunnel_nonce / tunnel_encrypt / tunnel_decrypt live in tunnel_aead.hpp so
// tests can pin their wire format with known-answer vectors.

// Blocking socket sends executed inside coroutine frames are unreliable on
// some MinGW/Asio combinations: the datagram is dropped while the call still
// reports success (verified with loopback probes). Perform the send in a
// posted non-coroutine handler and co_await its result instead.
//
// The resume signal lives in HEAP-OWNED shared state, not in the coroutine
// frame: the posted handler holds its own shared_ptr copy, so resumption can
// never destroy an object the handler still references (no use-after-free),
// and no overflow-prone duration::max() expiry is needed — on some platforms
// (Linux/glibc steady_clock) now + nanoseconds::max wraps to a PAST time
// point, which made the old frame-local timer fire immediately and race the
// handler into cancelling an already-destroyed object.
asio::awaitable<bool> post_udp_send(
    asio::io_context& io,
    asio::ip::udp::socket* transport,
    std::shared_ptr<std::vector<uint8_t>> payload,
    const asio::ip::udp::endpoint& endpoint) {
    if (!transport || !payload) co_return false;

    struct SendSignal {
        asio::steady_timer timer;
        explicit SendSignal(asio::io_context& context) : timer(context) {}
    };
    auto signal = std::make_shared<SendSignal>(io);
    auto ok = std::make_shared<bool>(false);

    // Keep the timer pending until the handler cancels it. A 24h horizon is
    // far beyond any send latency and cannot overflow the clock.
    using clock_t = asio::steady_timer::clock_type;
    signal->timer.expires_at(
        std::min(clock_t::now() + std::chrono::hours(24), clock_t::time_point::max()));

    asio::post(io, [transport, payload, endpoint, ok, signal]() {
        asio::error_code error;
        transport->send_to(asio::buffer(*payload), endpoint, 0, error);
        *ok = !error;
        signal->timer.cancel(); // resumes the waiter; last use of `signal`
    });

    try {
        co_await signal->timer.async_wait(asio::use_awaitable);
    } catch (const asio::system_error&) {
        // operation_aborted: the posted handler finished and cancelled us.
    }
    co_return *ok;
}

} // namespace

std::optional<std::map<std::string, std::string>> PQVPNNode::find_known_peer_by_pubkeys(
    const std::map<std::string, std::string>& payload) {
    static constexpr const char* public_keys[] = {
        "ed25519_pk", "brainpoolP512r1_pk", "kyber_pk", "mldsa_pk"
    };

    for (const auto& [peer_id, stored] : known_peers_) {
        (void)peer_id;
        for (const auto* key : public_keys) {
            const auto advertised = payload.find(key);
            const auto known = stored.find(key);
            if (advertised != payload.end() && known != stored.end() &&
                !advertised->second.empty() && !known->second.empty() &&
                normalize_public_key(advertised->second) == normalize_public_key(known->second)) {
                return stored;
            }
        }
    }
    return std::nullopt;
}

std::optional<PQVPNNode::PeerInfo> PQVPNNode::register_peer_from_hello(
    const std::map<std::string, std::string>& hello,
    const asio::ip::udp::endpoint& address) {
    const auto peer_id_it = hello.find("peerid");
    if (peer_id_it == hello.end()) {
        return std::nullopt;
    }

    const auto peer_id = decode_hex(peer_id_it->second);
    if (!peer_id) {
        return std::nullopt;
    }

    PeerInfo peer;
    peer.peer_id = *peer_id;
    peer.address = address;
    peer.last_seen = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    const auto nickname = hello.find("nickname");
    peer.nickname = nickname != hello.end() && !nickname->second.empty()
        ? nickname->second
        : hex_id(*peer_id) + "_peer";

    const auto relay = hello.find("relay");
    peer.is_relay = relay != hello.end() &&
        (relay->second == "true" || relay->second == "1" || relay->second == "yes");

    const auto parse_key = [&hello](const char* name) {
        const auto it = hello.find(name);
        if (it == hello.end() || it->second.empty()) {
            return std::vector<uint8_t>{};
        }
        const auto decoded = decode_hex(it->second);
        return decoded.value_or(std::vector<uint8_t>{});
    };
    peer.ed25519_pk = parse_key("ed25519_pk");
    peer.brainpoolP512r1_pk = parse_key("brainpoolP512r1_pk");
    peer.kyber_pk = parse_key("kyber_pk");
    peer.mldsa_pk = parse_key("mldsa_pk");
    peer.x25519_pk = parse_key("x25519_pk");
    peer.ml_kem_pk = parse_key("ml_kem_pk");

    const auto peer_hex = hex_id(peer.peer_id);

    // Full-tunnel gate: if this address cannot be pinned to the physical
    // gateway, admitting the peer would let its UDP transport fall into the TAP
    // default and loop through adapter re-encryption. Fail closed — reject the
    // registration (the peer may retry once routing is healthy) instead of
    // recording a peer we cannot reach without looping our own socket.
    if (!notify_peer_route(address, true)) {
        std::cerr << "rejecting HELLO registration from " << address
                  << ": route exclusion unavailable\n";
        return std::nullopt;
    }

    mesh.peers[peer_hex] = peer;
    auto& known = known_peers_[peer_hex];
    known["nickname"] = peer.nickname;
    known["ed25519_pk"] = hello.contains("ed25519_pk") ? hello.at("ed25519_pk") : "";
    known["brainpoolP512r1_pk"] = hello.contains("brainpoolP512r1_pk") ? hello.at("brainpoolP512r1_pk") : "";
    known["kyber_pk"] = hello.contains("kyber_pk") ? hello.at("kyber_pk") : "";
    known["mldsa_pk"] = hello.contains("mldsa_pk") ? hello.at("mldsa_pk") : "";
    known["x25519_pk"] = hello.contains("x25519_pk") ? hello.at("x25519_pk") : "";
    known["ml_kem_pk"] = hello.contains("ml_kem_pk") ? hello.at("ml_kem_pk") : "";
    known["is_relay"] = peer.is_relay ? "true" : "false";

    return peer;
}

// One pass of session upkeep, split from the timer loop so tests can drive it
// directly. The map is only iterated while no suspension is pending: stale
// sessions are pruned and established ones collected as shared_ptr copies in a
// synchronous first phase; the liveness PINGs (which suspend) run second,
// touching only those copies. Holding an unordered_map iterator or a reference
// into it across co_await would dangle if another handler inserted (rehash)
// or erased sessions while the send was in flight.
asio::awaitable<void> PQVPNNode::maintenance_tick() {
    const double now = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Expire in-flight handshakes whose S2 never arrived. The horizon is the
    // tunable handshake_timeout (default HANDSHAKE_TIMEOUT); the bootstrap loop
    // re-drives contact for peers without an established session.
    for (auto it = pending_handshakes_.begin(); it != pending_handshakes_.end();) {
        if (now - it->second.created_at > handshake_timeout) {
            it = pending_handshakes_.erase(it);
        } else {
            ++it;
        }
    }

    // Phase 1 (synchronous): prune, rekey, and snapshot established sessions.
    int active = 0;
    std::vector<std::shared_ptr<Session>> live_sessions;
    for (auto it = sessions_by_peer_id.begin(); it != sessions_by_peer_id.end();) {
        auto& sess = *(it->second);
        if (now - sess.last_activity > session_timeout) {
            std::cout << "Pruning stale session " << hex_id(sess.session_id).substr(0, 8) << std::endl;
            const auto remote = sess.remote_addr; // capture before the entry is erased
            it = sessions_by_peer_id.erase(it);
            // Release this peer's route exclusion only if no other consumer can
            // still send to its address. A live relay path (mesh entry) or a second
            // session at the same /32 would otherwise be left without an exclusion
            // and loop through the TAP default; keep it in that case so a later
            // re-establishment or mesh removal releases it cleanly.
            release_peer_route_if_unreferenced(remote);
            continue;
        }

        if (sess.state == SessionState::ESTABLISHED) {
            ++active;
            live_sessions.push_back(it->second);
            // Rekey is deliberately NOT performed here. main.py's maintenance
            // installs freshly derived keys at this point, but perform_rekey
            // derives them from LOCAL random entropy the peer can never know:
            // swapping them in unilaterally destroys an authenticated channel
            // (every later frame fails AEAD at the peer) with no security gain.
            // Until an authenticated key exchange exists, keep the working
            // keys rather than break traffic. RekeyManager remains available
            // as a tested primitive for that future exchange. Recorded in
            // MIGRATION_MANIFEST.md.
        }
        ++it;
    }

    // Phase 2 (suspends): tunnel-level liveness. The peer answers a PING with
    // a PONG (datagram_received), refreshing last_peer_response on both sides
    // so select_tunnel_peer can fail over silent peers. Replaces the legacy
    // type-4 heartbeat, which this codebase's tunnel dispatcher drops and
    // which only added observable dead traffic to the wire.
    for (const auto& session : live_sessions) {
        if (!session || !session->peer_id_.has_value()) continue;
        try {
            co_await ping_tunnel_peer(*session->peer_id_);
        } catch (...) {
            // One failed probe must not stop upkeep of the remaining peers.
        }
    }

    std::cout << "Session maintenance: active_sessions=" << active << std::endl;
    co_return;
}

asio::awaitable<void> PQVPNNode::session_maintenance() {
    std::cout << "Session maintenance task started" << std::endl;
    try {
        while (true) {
            try {
                co_await maintenance_tick();
            } catch (const std::exception& e) {
                std::cerr << "session_maintenance loop error: " << e.what() << std::endl;
            }
            asio::steady_timer timer(co_await asio::this_coro::executor);
            timer.expires_after(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::duration<double>(keepalive_interval)));
            co_await timer.async_wait(asio::use_awaitable);
        }
    } catch (const asio::system_error& e) {
        if (e.code() == asio::error::operation_aborted) {
            std::cout << "Session maintenance task cancelled" << std::endl;
        } else {
            std::cerr << "session_maintenance unexpected error: " << e.what() << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "session_maintenance unexpected error: " << e.what() << std::endl;
    }
    co_return;
}

// Resolves an 8-byte session hint against established sessions bound to the
// datagram's origin. Ambiguous hints fail closed, mirroring the tunnel data
// path in datagram_received().
std::shared_ptr<PQVPNNode::Session> find_tunnel_session(
    const std::unordered_map<
        std::vector<uint8_t>,
        std::shared_ptr<PQVPNNode::Session>,
        PQVPNNode::VectorHasher>& sessions,
    const std::vector<uint8_t>& hint,
    const asio::ip::udp::endpoint& endpoint) {
    if (hint.size() != 8) return nullptr;
    std::shared_ptr<PQVPNNode::Session> match;
    for (const auto& [peer_id, candidate] : sessions) {
        (void)peer_id;
        if (!candidate || candidate->state != PQVPNNode::SessionState::ESTABLISHED ||
            candidate->remote_addr != endpoint || candidate->session_id.size() < hint.size()) {
            continue;
        }
        if (std::equal(hint.begin(), hint.end(), candidate->session_id.begin())) {
            if (match) return nullptr; // Ambiguous truncated session identifier.
            match = candidate;
        }
    }
    return match;
}

asio::awaitable<void> PQVPNNode::datagram_received(
    std::vector<uint8_t> data,
    asio::ip::udp::endpoint endpoint) {
    if (data.size() < 16 || data[0] != 1) {
        co_return;
    }

    const auto payload_size = static_cast<std::size_t>(
        (static_cast<uint16_t>(data[14]) << 8) | data[15]);
    if (payload_size != data.size() - 16) {
        co_return;
    }

    // Control plane: HELLO registration and the S1/S2 hybrid handshake.
    // These frames carry a JSON body after the 16-byte outer header; the
    // established-session paths below keep their existing layout.
    if (data[1] == HELLO_FRAME || data[1] == S1_FRAME || data[1] == S2_FRAME) {
        std::vector<uint8_t> body(data.begin() + 16, data.end());
        if (data[1] == HELLO_FRAME) co_await handle_hello_frame(std::move(body), endpoint);
        else if (data[1] == S1_FRAME) co_await handle_s1_frame(std::move(body), endpoint);
        else co_await handle_s2_frame(std::move(body), endpoint);
        co_return;
    }

    if (data[1] == TUNNEL_PING || data[1] == TUNNEL_PONG) {
        // Tunnel liveness exchange: the authenticated tunnel-data layout with
        // an empty plaintext. The type byte is AAD-bound, so a peer cannot
        // forge or replay one against another session; the nonce window still
        // applies (recorded only after authentication succeeds).
        if (payload_size != 28) co_return;
        const std::vector<uint8_t> session_hint(data.begin() + 2, data.begin() + 10);
        auto session = find_tunnel_session(sessions_by_peer_id, session_hint, endpoint);
        if (!session || session->aead_recv_key.empty() || session->session_iv.size() != 12) {
            co_return;
        }

        const std::vector<uint8_t> nonce(data.begin() + 16, data.begin() + 28);
        const auto plaintext = tunnel_decrypt(
            std::span<const uint8_t>(data).subspan(28),
            session->aead_recv_key,
            nonce,
            std::span<const uint8_t>(data).first(16));
        // Liveness frames are direct tunnel frames: data_domain.
        if (!plaintext || !plaintext->empty() ||
            !check_and_record_nonce(*session, session->data_domain, nonce)) {
            co_return;
        }

        const double now = std::chrono::duration<double>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        session->last_peer_response = now;
        session->last_activity = now;
        if (data[1] == TUNNEL_PING) {
            // Answer exactly once with a PONG; a PONG never elicits a reply,
            // so the exchange cannot loop.
            const auto pong = build_tunnel_liveness_frame(TUNNEL_PONG, *session);
            if (pong && transport && !endpoint.address().is_unspecified()) {
                auto payload = std::make_shared<std::vector<uint8_t>>(std::move(*pong));
                co_await post_udp_send(io_context_, transport, std::move(payload), endpoint);
            }
        }
        co_return;
    }

    if (data[1] == RELAY_FRAME) {
        // Onion relay layer: payload = session_hint(8) + nonce(12) + ciphertext+tag.
        if (payload_size < 8 + 12 + 16) co_return;
        const auto outer_next_hash = std::vector<uint8_t>(data.begin() + 2, data.begin() + 10);
        const uint32_t circuit_id =
            (static_cast<uint32_t>(data[10]) << 24) |
            (static_cast<uint32_t>(data[11]) << 16) |
            (static_cast<uint32_t>(data[12]) << 8) |
            static_cast<uint32_t>(data[13]);
        const auto relay_hint = std::vector<uint8_t>(data.begin() + 16, data.begin() + 24);
        const auto relay_nonce = std::vector<uint8_t>(data.begin() + 24, data.begin() + 36);
        const auto relay_ciphertext = std::vector<uint8_t>(data.begin() + 36, data.end());
        co_await handle_relay(relay_hint, relay_nonce, relay_ciphertext,
            outer_next_hash, circuit_id, endpoint);
        co_return;
    }

    if (data[1] != TUNNEL_DATA_FRAME || payload_size < 28) {
        co_return;
    }

    const std::vector<uint8_t> session_hint(data.begin() + 2, data.begin() + 10);
    auto session = find_tunnel_session(sessions_by_peer_id, session_hint, endpoint);
    if (!session || session->aead_recv_key.empty() || session->session_iv.size() != 12) {
        co_return;
    }

    const std::vector<uint8_t> nonce(data.begin() + 16, data.begin() + 28);
    const auto plaintext = tunnel_decrypt(
        std::span<const uint8_t>(data).subspan(28),
        session->aead_recv_key,
        nonce,
        std::span<const uint8_t>(data).first(16));
    // Direct tunnel data: data_domain.
    if (!plaintext || plaintext->empty() ||
        !check_and_record_nonce(*session, session->data_domain, nonce)) {
        co_return;
    }

    session->bytes_recv += plaintext->size();
    const double now = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    session->last_activity = now;
    // Authenticated traffic from the peer is itself proof of liveness.
    session->last_peer_response = now;
    invoke_tunnel_sink(tunnel_packet_handler_, *plaintext, session->peer_id_.value_or({}));
    co_return;
}

std::optional<std::vector<uint8_t>> PQVPNNode::build_tunnel_liveness_frame(
    const uint8_t frame_type, Session& session) {
    // Liveness frames are the only authenticated empty-plaintext frames; any
    // other type would mint an out-of-contract frame shape.
    if (frame_type != TUNNEL_PING && frame_type != TUNNEL_PONG) return std::nullopt;
    if (session.state != SessionState::ESTABLISHED ||
        session.session_id.size() < 8 ||
        session.aead_send_key.empty() ||
        session.session_iv.size() != 12 ||
        session.nonce_send == std::numeric_limits<uint64_t>::max()) {
        return std::nullopt;
    }
    const auto nonce = tunnel_nonce(session.session_iv, ++session.nonce_send);
    const std::vector<uint8_t> session_hint(session.session_id.begin(), session.session_id.begin() + 8);
    // Empty plaintext: the frame carries no data, only authenticated liveness
    // (header(16) + nonce(12) + tag(16)).
    std::vector<uint8_t> reserved_payload(nonce.size() + 16);
    auto frame = encode_outer_frame(frame_type, session_hint, 0, reserved_payload);
    frame.resize(16);
    const auto tag = tunnel_encrypt(
        std::span<const uint8_t>{}, session.aead_send_key, nonce,
        std::span<const uint8_t>(frame));
    frame.insert(frame.end(), nonce.begin(), nonce.end());
    frame.insert(frame.end(), tag.begin(), tag.end());
    return frame;
}

asio::awaitable<bool> PQVPNNode::ping_tunnel_peer(const std::vector<uint8_t>& peer_id) {
    if (!transport) co_return false;
    const auto found = sessions_by_peer_id.find(peer_id);
    if (found == sessions_by_peer_id.end() || !found->second ||
        found->second->remote_addr.address().is_unspecified()) {
        co_return false;
    }
    // Hold a shared_ptr copy across the suspension: the map may rehash or
    // erase this session while the send is in flight, and a reference or
    // iterator would dangle on resume.
    auto session = found->second;
    const auto frame = build_tunnel_liveness_frame(TUNNEL_PING, *session);
    if (!frame) co_return false;
    const auto frame_size = frame->size();
    auto payload = std::make_shared<std::vector<uint8_t>>(std::move(*frame));
    const auto endpoint = session->remote_addr;
    const bool sent = co_await post_udp_send(io_context_, transport, std::move(payload), endpoint);
    if (sent) {
        session->bytes_sent += frame_size;
        // A successful UDP handoff only proves the local socket accepted the
        // datagram — it says nothing about whether the peer is alive. Do NOT
        // refresh last_activity here: a silent peer would otherwise evade the
        // SESSION_TIMEOUT prune forever (probes every 30s < 1h horizon). Only
        // authenticated inbound frames (PONG, tunnel data, relay peel) count.
    }
    co_return sent;
}

std::optional<std::vector<uint8_t>> PQVPNNode::build_tunnel_datagram(
    const std::vector<uint8_t>& peer_id,
    const std::span<const uint8_t> packet) {
    if (packet.empty() || packet.size() > UINT16_MAX - 28) return std::nullopt;
    const auto found = sessions_by_peer_id.find(peer_id);
    if (found == sessions_by_peer_id.end() || !found->second ||
        found->second->state != SessionState::ESTABLISHED ||
        found->second->session_id.size() < 8 ||
        found->second->aead_send_key.empty() ||
        found->second->session_iv.size() != 12 ||
        found->second->nonce_send == std::numeric_limits<uint64_t>::max()) {
        return std::nullopt;
    }

    auto& session = *found->second;
    const auto nonce = tunnel_nonce(session.session_iv, ++session.nonce_send);
    const std::vector<uint8_t> session_hint(session.session_id.begin(), session.session_id.begin() + 8);
    const auto encrypted_size = packet.size() + 16;
    const auto payload_size = nonce.size() + encrypted_size;
    std::vector<uint8_t> reserved_payload(payload_size);
    auto frame = encode_outer_frame(TUNNEL_DATA_FRAME, session_hint, 0, reserved_payload);
    frame.resize(16);
    const auto encrypted = tunnel_encrypt(packet, session.aead_send_key, nonce,
        std::span<const uint8_t>(frame));
    frame.insert(frame.end(), nonce.begin(), nonce.end());
    frame.insert(frame.end(), encrypted.begin(), encrypted.end());
    session.bytes_sent += packet.size();
    // Outbound construction never refreshes last_activity: freshness is
    // receive-side proof of life only (see ping_tunnel_peer). A peer that
    // never answers must stay prunable instead of being kept alive by our own
    // sends.
    return frame;
}

bool PQVPNNode::send_tunnel_packet(
    const std::vector<uint8_t>& peer_id,
    const std::span<const uint8_t> packet) {
    const auto datagram = build_tunnel_datagram(peer_id, packet);
    if (!datagram || !transport) return false;
    const auto found = sessions_by_peer_id.find(peer_id);
    if (found == sessions_by_peer_id.end() || !found->second ||
        found->second->remote_addr.address().is_unspecified()) return false;
    asio::error_code error;
    transport->send_to(asio::buffer(*datagram), found->second->remote_addr, 0, error);
    return !error;
}

std::optional<std::vector<uint8_t>> PQVPNNode::select_tunnel_peer() const {
    const double now = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const std::vector<uint8_t>* best = nullptr;
    double best_activity = 0.0;
    for (const auto& [peer_id, session] : sessions_by_peer_id) {
        if (!session || session->state != SessionState::ESTABLISHED) continue;
        if (session->remote_addr.address().is_unspecified()) continue;
        // Silent peers are excluded: without a recent authenticated response
        // the packet would be delivered to a black hole, and UDP sends report
        // success either way. Failing closed here is the safe behavior.
        if (now - session->last_peer_response > liveness_window) continue;
        const bool better = best == nullptr
            ? true
            : session->last_activity > best_activity
              || (session->last_activity == best_activity && peer_id < *best);
        if (better) {
            best = &peer_id;
            best_activity = session->last_activity;
        }
    }
    return best ? std::optional<std::vector<uint8_t>>(*best) : std::nullopt;
}

asio::awaitable<bool> PQVPNNode::forward_adapter_packet(std::vector<uint8_t> packet) {
    if (packet.empty() || !transport) co_return false;
    try {
        const auto peer = select_tunnel_peer();
        if (!peer) co_return false;
        const auto datagram = build_tunnel_datagram(*peer, std::span<const uint8_t>(packet));
        if (!datagram) co_return false;
        const auto found = sessions_by_peer_id.find(*peer);
        if (found == sessions_by_peer_id.end() || !found->second ||
            found->second->remote_addr.address().is_unspecified()) {
            co_return false;
        }
        // Posted send on the io_context: the adapter reader thread must not
        // touch the Asio socket directly (see post_udp_send).
        auto payload = std::make_shared<std::vector<uint8_t>>(std::move(*datagram));
        const auto endpoint = found->second->remote_addr;
        co_return co_await post_udp_send(io_context_, transport, std::move(payload), endpoint);
    } catch (const std::exception& error) {
        // Adapter-originated forwarding must never take the node down.
        std::cerr << "adapter packet forwarding failed: " << error.what() << "\n";
        co_return false;
    } catch (...) {
        std::cerr << "adapter packet forwarding failed with an unknown exception\n";
        co_return false;
    }
}

std::optional<std::vector<uint8_t>> PQVPNNode::choose_relay(
    const std::vector<uint8_t>& destination) {
    std::vector<const PeerInfo*> candidates;
    candidates.reserve(mesh.peers.size());
    for (const auto& [id, peer] : mesh.peers) {
        (void)id;
        if (peer.peer_id != destination && (!my_id_ || peer.peer_id != *my_id_)) {
            candidates.push_back(&peer);
        }
    }
    std::sort(candidates.begin(), candidates.end(), [](const PeerInfo* left, const PeerInfo* right) {
        if (left->is_relay != right->is_relay) return left->is_relay > right->is_relay;
        return left->peer_id < right->peer_id;
    });
    if (candidates.empty()) return std::nullopt;
    return candidates.front()->peer_id;
}

void PQVPNNode::add_known_peer(const std::vector<uint8_t>& peer_id) {
    known_peers_.try_emplace(hex_id(peer_id));
}

void PQVPNNode::save_known_peers() {
    nlohmann::json document = nlohmann::json::object();
    document["peers"] = known_peers_;
    const auto destination = std::filesystem::path(known_peers_file_);
    const auto temporary = destination.string() + ".tmp";
    {
        std::ofstream output(temporary, std::ios::trunc);
        if (!output) throw std::runtime_error("cannot open known-peers temporary file");
        output << document.dump(2) << '\n';
        if (!output) throw std::runtime_error("cannot write known-peers temporary file");
    }
    std::filesystem::rename(temporary, destination);
}

void PQVPNNode::load_known_peers() {
    std::ifstream input(known_peers_file_);
    if (!input) return;
    try {
        const auto document = nlohmann::json::parse(input);
        if (!document.contains("peers") || !document["peers"].is_object()) return;
        known_peers_.clear();
        for (const auto& [identity, value] : document["peers"].items()) {
            if (value.is_object()) {
                known_peers_[identity] = value.get<std::map<std::string, std::string>>();
            }
        }
    } catch (const nlohmann::json::exception&) {
        return;
    }
}

bool PQVPNNode::register_peer_tofu(
    const std::vector<uint8_t>& peer_id,
    const std::map<std::string, std::string>& info) {
    if (peer_id.empty()) return false;
    const auto identity = hex_id(peer_id);
    const auto existing = known_peers_.find(identity);
    if (existing != known_peers_.end()) {
        static constexpr const char* identity_keys[] = {
            "ed25519_pk", "brainpoolP512r1_pk", "kyber_pk", "mldsa_pk"
        };
        for (const auto* key : identity_keys) {
            const auto old_value = existing->second.find(key);
            const auto new_value = info.find(key);
            if (old_value != existing->second.end() && new_value != info.end() &&
                !old_value->second.empty() && old_value->second != new_value->second) {
                return false;
            }
        }
    }
    known_peers_[identity] = info;
    return known_peers_.contains(identity);
}

std::vector<uint8_t> PQVPNNode::session_salt(const std::vector<uint8_t>& peer_id) const {
    std::vector<uint8_t> material = my_id_.value_or(std::vector<uint8_t>{});
    material.insert(material.end(), peer_id.begin(), peer_id.end());
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(material.data(), material.size(), digest.data());
    digest.resize(16);
    return digest;
}

bool PQVPNNode::establish_identity() {
    // Keep an identity that was set explicitly (tests, or a future key loader).
    // Otherwise derive it from the ed25519 public key — the node's primary
    // authentication/identity key. main.py derives my_id from the brainpoolP512r1
    // key instead (main.py:2193-2209); using ed25519 keeps identity tied to the
    // auth key and is recorded in MIGRATION_MANIFEST.md. Deriving it here lets a
    // production node relay and deliver locally, since handle_relay binds its AAD
    // to peer_hash8(my_id) and needs it set.
    if (!my_id_.has_value()) {
        if (ed25519_public_key.empty()) return false;
        std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
        SHA256(ed25519_public_key.data(), ed25519_public_key.size(), digest.data());
        my_id_ = std::move(digest);
    }
    return my_id_.has_value() && !my_id_->empty();
}

bool PQVPNNode::is_peer_allowed(const std::vector<uint8_t>& peer_id) const {
    const auto identity = hex_id(peer_id);
    if (!allowlist_.empty()) return allowlist_.contains(identity);
    const bool previously_known = known_peers_.contains(identity);
    return previously_known || tofu_enabled_;
}

// Strictly monotonic within the given domain: a counter at or below the
// domain's high-water mark is a replay, and a counter already seen in the
// bounded window is rejected. Domains are independent (see Session::NonceDomain),
// so an onion layer accepted into relay_domain never evicts a lower fresh
// tunnel-data counter from data_domain — or vice versa.
bool PQVPNNode::check_and_record_nonce(Session& session, Session::NonceDomain& domain,
                                       const std::vector<uint8_t>& nonce) const {
    if (nonce.size() != 12) return false;
    const std::array<uint8_t, 4> expected_prefix = session.session_iv.size() >= 4
        ? std::array<uint8_t, 4>{session.session_iv[0], session.session_iv[1], session.session_iv[2], session.session_iv[3]}
        : std::array<uint8_t, 4>{0, 0, 0, 0};
    if (!std::equal(expected_prefix.begin(), expected_prefix.end(), nonce.begin())) return false;
    uint64_t counter = 0;
    for (std::size_t index = 4; index < nonce.size(); ++index) {
        counter = (counter << 8) | nonce[index];
    }
    if (counter <= domain.high_water || domain.window.contains(counter)) return false;
    domain.high_water = counter;
    domain.window.insert(counter);
    while (domain.window.size() > session.replay_window_size) {
        domain.window.erase(domain.window.begin());
    }
    return domain.window.contains(counter);
}

std::vector<uint8_t> PQVPNNode::make_outer_frame(
    const uint8_t frame_type,
    const std::vector<uint8_t>& hop_id,
    const uint32_t circuit_id,
    const std::vector<uint8_t>& payload) const {
    return encode_outer_frame(frame_type, hop_id, circuit_id, payload);
}

// Builds the five-part relay AAD: "PQVPN" + full session id + 8-byte identity
// hash of the node that peels this layer + 8-byte identity hash of the node
// expected to SEND it (the onion source for hop one, the preceding relay for
// later hops) + circuit id (big-endian). Binding the expected forwarder's
// identity — not merely checking its address at verification time — stops a
// registered peer from injecting a captured layer that was built for a
// different forwarder. Builder and handler must use this single construction.
std::vector<uint8_t> relay_aad(
    const std::vector<uint8_t>& session_id,
    const std::vector<uint8_t>& peeler_hash,
    const std::vector<uint8_t>& sender_hash,
    uint32_t circuit_id) {
    std::vector<uint8_t> aad{'P', 'Q', 'V', 'P', 'N'};
    aad.insert(aad.end(), session_id.begin(), session_id.end());
    aad.insert(aad.end(), peeler_hash.begin(), peeler_hash.end());
    aad.insert(aad.end(), sender_hash.begin(), sender_hash.end());
    for (int shift = 24; shift >= 0; shift -= 8) {
        aad.push_back(static_cast<uint8_t>((circuit_id >> shift) & 0xff));
    }
    return aad;
}

std::optional<std::vector<uint8_t>> PQVPNNode::build_onion_frame(
    const std::vector<std::vector<uint8_t>>& path,
    const std::vector<uint8_t>& inner_frame) {
    return build_onion_frame_with_circuit(path, inner_frame, 0);
}

std::optional<std::vector<uint8_t>> PQVPNNode::build_onion_frame_with_circuit(
    const std::vector<std::vector<uint8_t>>& path,
    const std::vector<uint8_t>& inner_frame,
    const uint32_t circuit_id) {
    // main.py accepts a one-element path and emits a RELAY frame whose payload
    // is raw content, because its encryption loop never runs for such paths.
    // Every RELAY receiver parses its payload as session hint + nonce +
    // ciphertext, so that shape can never be delivered — and send_onion would
    // report success for content that provably never arrives. The builder
    // therefore rejects paths shorter than two elements (fail-closed); direct
    // delivery to a single peer uses build_tunnel_datagram. Recorded in
    // MIGRATION_MANIFEST.md.
    if (path.size() < 2) return std::nullopt;

    // main.py build_onion_frame_with_circuit: encrypt from the end of the path
    // back to the start. Each layer is encrypted with the session shared with
    // the hop that will peel it, and its plaintext is prefixed with the 8-byte
    // identity hash of the next hop after peeling. A missing session for any
    // intermediate hop fails closed (main.py returns None).
    std::vector<uint8_t> current_inner = inner_frame;
    // main.py: for i in range(len(path) - 1, 0, -1)
    for (std::size_t idx = path.size() - 1; idx >= 1; --idx) {
        const auto& target = path[idx];
        const auto& hop = path[idx - 1];
        // Only ESTABLISHED sessions can carry a layer: the receiving relay
        // resolves its hint against established sessions, so a layer built on
        // a handshaking/closing/closed session could never be peeled.
        const auto found = sessions_by_peer_id.find(hop);
        if (found == sessions_by_peer_id.end() || !found->second ||
            found->second->state != SessionState::ESTABLISHED) {
            return std::nullopt;
        }
        auto& session = *found->second;
        if ((session.aead_send_key.size() != 16 && session.aead_send_key.size() != 32) ||
            session.session_iv.size() != 12 || session.session_id.size() < 8 ||
            session.nonce_send == std::numeric_limits<uint64_t>::max()) {
            return std::nullopt;
        }

        const auto next_hash = peer_hash8(target);
        // The node that will SEND this layer to the peeler: the onion source
        // for the outermost layer, the preceding relay for every inner one.
        std::vector<uint8_t> expected_sender;
        if (idx == 1) {
            // Without a local identity there is no source hash to bind; fail
            // closed rather than emit an unbound outer layer.
            if (!my_id_.has_value()) return std::nullopt;
            expected_sender = *my_id_;
        } else {
            expected_sender = path[idx - 2];
        }
        const auto sender_hash = peer_hash8(expected_sender);

        // AAD: "PQVPN" + full session id + peeler hash + expected-sender hash
        // + circuit id (BE). main.py bound the *target* hash here, which its
        // own handle_relay could not reproduce; binding the peeler is the
        // minimal self-consistent reading of that AAD. Binding the expected
        // forwarder's identity additionally stops a registered peer from
        // injecting a captured layer built for a different forwarder — the
        // handler verifies the actual sender against this hash. Recorded in
        // MIGRATION_MANIFEST.md.
        const auto aad = relay_aad(session.session_id, peer_hash8(hop),
                                   sender_hash, circuit_id);

        const auto nonce = tunnel_nonce(session.session_iv, ++session.nonce_send);
        std::vector<uint8_t> plaintext = next_hash;
        plaintext.insert(plaintext.end(), current_inner.begin(), current_inner.end());

        std::vector<uint8_t> ciphertext_and_tag;
        try {
            ciphertext_and_tag = tunnel_encrypt(
                std::span<const uint8_t>(plaintext), session.aead_send_key, nonce,
                std::span<const uint8_t>(aad));
        } catch (const std::exception&) {
            return std::nullopt;
        }

        // Layer blob: session_hint(8) + nonce(12) + ciphertext+tag.
        current_inner.assign(session.session_id.begin(), session.session_id.begin() + 8);
        current_inner.insert(current_inner.end(), nonce.begin(), nonce.end());
        current_inner.insert(current_inner.end(), ciphertext_and_tag.begin(), ciphertext_and_tag.end());
    }

    // Outer frame addressed to the first hop (main.py: make_outer_frame(FT_RELAY,
    // peer_hash8(path[0]), circuit_id, ...)).
    return encode_outer_frame(RELAY_FRAME, peer_hash8(path[0]), circuit_id, current_inner);
}

std::shared_ptr<PQVPNNode::Session> PQVPNNode::establish_hybrid_session(
    const std::vector<uint8_t>& peer_id,
    const asio::ip::udp::endpoint& remote_endpoint,
    const std::vector<uint8_t>& x25519_secret,
    const std::vector<uint8_t>& ml_kem_secret,
    const std::vector<uint8_t>& handshake_transcript,
    const bool initiator) {
    if (peer_id.empty() || remote_endpoint.address().is_unspecified()) {
        throw std::invalid_argument("hybrid session requires a peer identity and remote endpoint");
    }

    // Full-tunnel gate (see register_peer_from_hello): a session whose peer
    // address cannot be excluded from the TAP default would loop its own
    // transport traffic, so refuse to establish it. No hook installed means no
    // full-tunnel routing is active and there is nothing to gate on.
    if (!notify_peer_route(remote_endpoint, true)) {
        std::cerr << "refusing hybrid session with " << remote_endpoint
                  << ": route exclusion unavailable\n";
        return nullptr;
    }

    const auto material = crypto::combine_hybrid_secrets(
        x25519_secret, ml_kem_secret, handshake_transcript, 92);
    const std::vector<uint8_t> initiator_to_responder(material.begin(), material.begin() + 32);
    const std::vector<uint8_t> responder_to_initiator(material.begin() + 32, material.begin() + 64);

    auto session = std::make_shared<Session>();
    session->session_id.assign(material.begin() + 76, material.end());
    session->peer_id_ = peer_id;
    session->remote_addr = remote_endpoint;
    session->aead_send_key = initiator ? initiator_to_responder : responder_to_initiator;
    session->aead_recv_key = initiator ? responder_to_initiator : initiator_to_responder;
    session->session_iv.assign(material.begin() + 64, material.begin() + 76);
    session->state = SessionState::ESTABLISHED;
    // The node's configured replay window (default 1024) bounds each
    // session's nonce domains; a deployment may retune it via config.
    session->replay_window_size = replay_window_size;
    session->created_at = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    session->last_activity = session->created_at;
    // A fresh session is considered live until the first missed liveness
    // window, so selection does not drop it before any PING/PONG has flown.
    session->last_peer_response = session->created_at;
    sessions_by_peer_id[peer_id] = session;
    return session;
}

bool PQVPNNode::notify_peer_route(const asio::ip::udp::endpoint& address, const bool add) {
    // No hook installed means full-tunnel routing is not active; an
    // unspecified address has nowhere to be pinned. In both cases the
    // requested state change trivially holds, so admission proceeds.
    if (!peer_route_hook_ || address.address().is_unspecified()) {
        const bool ok = true;
        return ok;
    }
    try {
        return peer_route_hook_(address, add);
    } catch (const std::exception& error) {
        // A hook that throws is a failed state change: admission paths fail
        // closed rather than admitting an unexcluded peer.
        std::cerr << "peer route hook failed: " << error.what() << "\n";
    } catch (...) {
    }
    return false;
}

void PQVPNNode::release_peer_route_if_unreferenced(const asio::ip::udp::endpoint& address) {
    // A consumer is anything that can still send UDP to this exact endpoint without a
    // local session: another established session at the same endpoint, or a relay-capable
    // mesh entry (non-empty peer id — the only shape handle_relay will forward to). While
    // any such consumer exists, dropping the exclusion would let its transport fall into
    // the TAP default and loop through adapter re-encryption. Compare full endpoints, not
    // just the address: PeerRouteManager refcounts each endpoint independently on a shared
    // /32 (see remove_peer's still_referenced check), so releasing this one keeps the OS
    // route alive for other ports without leaking a stale reference when none remain.
    for (const auto& [peer_id, session] : sessions_by_peer_id) {
        if (session && session->remote_addr == address) return;
    }
    for (const auto& [hex, info] : mesh.peers) {
        if (!info.peer_id.empty() && info.address == address) return;
    }
    notify_peer_route(address, false);
}

asio::awaitable<bool> PQVPNNode::send_onion(
    const std::vector<std::vector<uint8_t>>& path,
    const std::vector<uint8_t>& inner_frame) {
    const auto frame = build_onion_frame(path, inner_frame);
    if (!frame || path.empty() || !transport) co_return false;
    // The outer frame is addressed to the first hop (main.py send_onion).
    const auto found = sessions_by_peer_id.find(path[0]);
    if (found == sessions_by_peer_id.end() || !found->second ||
        found->second->remote_addr.address().is_unspecified()) co_return false;

    // Shared_ptr copy across the suspension: the map may rehash or erase this
    // session while the send is in flight.
    auto session = found->second;
    const auto frame_size = frame->size();
    auto payload = std::make_shared<std::vector<uint8_t>>(std::move(*frame));
    const auto endpoint = session->remote_addr;
    const bool sent = co_await post_udp_send(io_context_, transport, std::move(payload), endpoint);
    if (sent) {
        session->bytes_sent += frame_size;
        // Outbound send success is not proof of life: last_activity stays
        // receive-side only, so a silent peer remains prunable (see
        // ping_tunnel_peer).
    }
    co_return sent;
}

namespace {

// Resolves a truncated session identifier (first 8 bytes) to exactly one
// established session. Ambiguous or unknown hints fail closed, mirroring the
// tunnel data path in datagram_received().
std::optional<std::shared_ptr<pqvpn::PQVPNNode::Session>> find_session_by_hint(
    const std::unordered_map<
        std::vector<uint8_t>,
        std::shared_ptr<pqvpn::PQVPNNode::Session>,
        pqvpn::PQVPNNode::VectorHasher>& sessions,
    const std::vector<uint8_t>& hint) {
    if (hint.size() != 8) return std::nullopt;
    std::shared_ptr<pqvpn::PQVPNNode::Session> match;
    for (const auto& [peer_id, candidate] : sessions) {
        (void)peer_id;
        if (!candidate || candidate->state != pqvpn::PQVPNNode::SessionState::ESTABLISHED ||
            candidate->session_id.size() < hint.size()) {
            continue;
        }
        if (std::equal(hint.begin(), hint.end(), candidate->session_id.begin())) {
            if (match) return std::nullopt; // Ambiguous truncated identifier.
            match = candidate;
        }
    }
    return match;
}

} // namespace

asio::awaitable<bool> PQVPNNode::handle_relay(
    const std::vector<uint8_t>& session_hint,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext_and_tag,
    const std::vector<uint8_t>& outer_next_hash,
    uint32_t circuit_id,
    const asio::ip::udp::endpoint& sender) {
    // main.py handle_relay: decrypt one onion layer and either forward the
    // inner content to the next hop or deliver it locally.
    auto session = find_session_by_hint(sessions_by_peer_id, session_hint);
    if (!session || !*session) co_return false;
    auto& sess = **session;

    // Sender binding (hardening beyond main.py, whose handle_relay takes no
    // address). The layer's AAD binds the identity of the node expected to
    // SEND it — the onion source for hop one, the preceding relay for later
    // hops. Verification therefore requires BOTH: the actual UDP sender must
    // be a plausible forwarder (the session's own peer at its registered
    // endpoint, or a mesh-registered peer at that address), AND the AEAD tag
    // must verify under that identity's hash. A captured valid layer replayed
    // by any OTHER registered peer fails the second check: its AAD names a
    // different forwarder. The monotonic nonce window additionally rejects
    // replays after first delivery, so an unregistered address can neither
    // forge nor replay a valid layer.
    std::vector<std::vector<uint8_t>> sender_candidates;
    if (sess.peer_id_.has_value() && sess.remote_addr == sender) {
        sender_candidates.push_back(peer_hash8(*sess.peer_id_));
    }
    for (const auto& [peer_hex, info] : mesh.peers) {
        (void)peer_hex;
        if (!info.peer_id.empty() && info.address == sender) {
            const auto hash = peer_hash8(info.peer_id);
            if (std::find(sender_candidates.begin(), sender_candidates.end(), hash)
                    == sender_candidates.end()) {
                sender_candidates.push_back(hash);
            }
        }
    }
    if (sender_candidates.empty()) co_return false;

    // A relay must know its own identity: it binds the layer AAD and decides
    // local delivery (main.py: nexth == peer_hash8(my_id)).
    if (!my_id_.has_value()) co_return false;
    const auto self_hash = peer_hash8(*my_id_);

    // The outer header's next-hop field must identify this node for the layer
    // it peels; the builder binds the same value into the AAD.
    if (outer_next_hash != self_hash) co_return false;

    // Try each endpoint-qualified candidate identity: exactly one can verify
    // (the AAD names a specific forwarder), and a failed tag attempt reveals
    // nothing beyond "not this identity".
    std::optional<std::vector<uint8_t>> plaintext;
    for (const auto& candidate : sender_candidates) {
        const auto aad = relay_aad(sess.session_id, self_hash, candidate, circuit_id);
        plaintext = tunnel_decrypt(
            std::span<const uint8_t>(ciphertext_and_tag), sess.aead_recv_key, nonce,
            std::span<const uint8_t>(aad));
        if (plaintext && plaintext->size() >= 9) break; // nexth(8) + >=1 content byte
    }
    if (!plaintext || plaintext->size() < 9) co_return false;

    // Replay defense: strictly monotonic counter within relay_domain.
    // Recorded only after authentication succeeds, so an invalid-tag packet
    // cannot advance the replay window and evict a legitimate nonce (same
    // order as the tunnel data path in datagram_received). The domain is
    // separate from data_domain on purpose: this layer's counter must not
    // evict the lower counter of the tunnel data frame it carries, which is
    // checked against data_domain after local delivery.
    if (!check_and_record_nonce(sess, sess.relay_domain, nonce)) co_return false;

    const auto next_hash = std::vector<uint8_t>(plaintext->begin(), plaintext->begin() + 8);
    const auto inner_frame = std::vector<uint8_t>(plaintext->begin() + 8, plaintext->end());

    sess.bytes_recv += ciphertext_and_tag.size();
    const double relay_now = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    sess.last_activity = relay_now;
    // An authenticated relay layer is proof the peeling peer is alive.
    sess.last_peer_response = relay_now;

    if (next_hash == self_hash) {
        // Local delivery: the peeled content is a complete outer frame for this
        // node. main.py dispatches FT_DATA to handle_data; in this codebase the
        // established sink for decrypted application packets is
        // tunnel_packet_handler_ (see datagram_received). Anything else fails
        // closed, as the reference leaves that dispatch unfinished.
        uint8_t frame_type = 0;
        std::vector<uint8_t> body;
        bool headered = false;
        if (inner_frame.size() >= 16 && inner_frame[0] == 1) {
            frame_type = inner_frame[1];
            const auto length = static_cast<std::size_t>(
                (static_cast<uint16_t>(inner_frame[14]) << 8) | inner_frame[15]);
            if (16 + length > inner_frame.size()) co_return false;
            body.assign(inner_frame.begin() + 16, inner_frame.begin() + 16 + length);
            headered = true;
        } else {
            // main.py fallback shape: type byte followed by raw payload. The
            // tunnel data layout requires the 16-byte header, so this branch
            // can never be delivered below.
            if (inner_frame.empty()) co_return false;
            frame_type = inner_frame[0];
            body.assign(inner_frame.begin() + 1, inner_frame.end());
        }

        // Only the tunnel data layout built by build_tunnel_datagram is
        // accepted: headered TUNNEL_DATA_FRAME with nonce(12) + ciphertext+tag.
        // main.py's FT_DATA body carries its own session id first and this
        // codebase has no builder for that shape, so it fails closed. The body
        // length (not the frame size) bounds every slice taken below.
        const bool deliverable_data =
            headered && frame_type == TUNNEL_DATA_FRAME && tunnel_packet_handler_ &&
            body.size() >= 12 + 16;
        if (!deliverable_data) co_return false;

        // The inner data frame carries its own session hint in the header
        // (main.py: handle_data(session_id, ...)); resolve it independently.
        const auto data_hint = std::vector<uint8_t>(inner_frame.begin() + 2,
            inner_frame.begin() + 10);
        auto data_session = find_session_by_hint(sessions_by_peer_id, data_hint);
        if (!data_session || !*data_session) co_return false;
        auto& data_sess = **data_session;

        // Tunnel data layout: nonce(12) + ciphertext+tag, AEAD-bound to the
        // frame header (build_tunnel_datagram / datagram_received).
        const auto data_nonce = std::vector<uint8_t>(body.begin(), body.begin() + 12);
        const auto data_ciphertext = std::span<const uint8_t>(body).subspan(12);
        const auto packet = tunnel_decrypt(
            data_ciphertext, data_sess.aead_recv_key, data_nonce,
            std::span<const uint8_t>(inner_frame).first(16));
        if (!packet || packet->empty()) co_return false;
        // The inner frame is a direct tunnel-data frame: data_domain. It may
        // share its session with the layer just peeled (relay_domain) — the
        // split domains keep its lower counter from being rejected as a replay.
        if (!check_and_record_nonce(data_sess, data_sess.data_domain, data_nonce)) co_return false;

        invoke_tunnel_sink(tunnel_packet_handler_, *packet, data_sess.peer_id_.value_or({}));
        data_sess.bytes_recv += body.size();
        co_return true;
    }

    // Forward the peeled layer to the next hop: resolve the 8-byte identity
    // hash against mesh.peers. The relay only needs the peer's network
    // address, not a local session with it — the layer is already encrypted
    // for whoever peels it next.
    const PeerInfo* target = nullptr;
    std::size_t matches = 0;
    for (const auto& [peer_hex, candidate] : mesh.peers) {
        if (!candidate.peer_id.empty() && peer_hash8(candidate.peer_id) == next_hash) {
            ++matches;
            target = &candidate;
        }
    }
    // A truncated hash matching zero known peers is an unknown next hop; one
    // matching several is ambiguous and fails closed rather than risking
    // delivery to the wrong node (main.py takes the first match in dict order).
    if (matches != 1 || target->address.address().is_unspecified() || !transport) {
        co_return false;
    }

    // Wrap the peeled layer in a fresh RELAY_FRAME before sending. main.py
    // forwards the raw inner blob, but every dispatcher — including main.py's
    // own _process_outer_datagram — requires the 16-byte outer header before
    // routing to handle_relay, so a raw forward is undeliverable at hop two.
    // The new header identifies the next peeler (next_hash) and preserves the
    // circuit id, which the builder bound into every layer's AAD; the payload
    // length is set by encode_outer_frame. Recorded in MIGRATION_MANIFEST.md.
    const auto wrapped = encode_outer_frame(RELAY_FRAME, next_hash, circuit_id, inner_frame);
    auto payload = std::make_shared<std::vector<uint8_t>>(std::move(wrapped));
    const auto endpoint = target->address;
    if (!co_await post_udp_send(io_context_, transport, std::move(payload), endpoint)) {
        co_return false;
    }

    co_return true;
}

// ============================================================================
// Hybrid handshake control plane (HELLO / S1 / S2)
// ============================================================================

bool PQVPNNode::load_or_create_identity() {
    using pqvpn::identity::NodeIdentity;
    std::error_code ec;
    const auto config_file = std::filesystem::path(config_path_);
    const auto directory = config_file.has_parent_path()
        ? config_file.parent_path()
        : std::filesystem::current_path(ec);
    const auto file = (directory / "node_keys.json").string();

    NodeIdentity identity;
    bool needs_generation = false;
    if (std::filesystem::exists(file, ec)) {
        try {
            identity = NodeIdentity::load(file);
        } catch (const std::exception& error) {
            std::cerr << "node identity load failed (" << error.what()
                      << "); generating a fresh one\n";
            needs_generation = true;
        }
    } else {
        needs_generation = true;
    }

    if (needs_generation) {
        try {
            identity = NodeIdentity::generate();
        } catch (const std::exception& error) {
            std::cerr << "node identity generation failed: " << error.what() << "\n";
            return false;
        }
        try {
            identity.save(file);
        } catch (const std::exception& error) {
            std::cerr << "warning: could not persist node identity ("
                      << error.what() << "); it will not survive a restart\n";
        }
    }

    ed25519_private_key = identity.ed25519_sk;
    ed25519_public_key = identity.ed25519_pk;
    x25519_private_key = identity.x25519_sk;
    x25519_public_key = identity.x25519_pk;
    ml_kem_secret_key = identity.ml_kem_sk;
    ml_kem_public_key = identity.ml_kem_pk;
    ml_dsa_private_key = identity.mldsa_sk;
    ml_dsa_public_key = identity.mldsa_pk;
    return !ed25519_private_key.empty();
}

std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> PQVPNNode::peer_hybrid_keys(
    const std::vector<uint8_t>& peer_id) const {
    if (const auto* peer = mesh.get_peer(peer_id);
        peer && !peer->x25519_pk.empty() && !peer->ml_kem_pk.empty()) {
        return std::make_pair(peer->x25519_pk, peer->ml_kem_pk);
    }
    const auto known = known_peers_.find(hex_id(peer_id));
    if (known != known_peers_.end()) {
        auto decode = [&](const char* name) -> std::vector<uint8_t> {
            const auto it = known->second.find(name);
            if (it == known->second.end() || it->second.empty()) return {};
            return decode_hex(it->second).value_or(std::vector<uint8_t>{});
        };
        auto x25519_pk = decode("x25519_pk");
        auto ml_kem_pk = decode("ml_kem_pk");
        if (!x25519_pk.empty() && !ml_kem_pk.empty()) {
            return std::make_pair(std::move(x25519_pk), std::move(ml_kem_pk));
        }
    }
    return std::nullopt;
}

asio::awaitable<void> PQVPNNode::handle_hello_frame(
    std::vector<uint8_t> payload, const asio::ip::udp::endpoint& endpoint) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(payload);
    } catch (const std::exception&) {
        co_return; // not a HELLO body
    }
    if (!j.is_object()) co_return;

    if (!verify_hybrid_signatures(j, kHelloFields)) {
        std::cerr << "rejecting HELLO from " << endpoint
                  << ": hybrid signature verification failed\n";
        co_return;
    }

    const auto peer_id = hex_field(j, "peerid");
    if (!peer_id || peer_id->empty()) co_return;
    if (my_id_.has_value() && *peer_id == *my_id_) co_return; // self-addressed
    if (!is_peer_allowed(*peer_id)) {
        std::cerr << "rejecting HELLO from " << endpoint << ": peer not allowed\n";
        co_return;
    }

    std::map<std::string, std::string> hello_map;
    for (const auto& [key, value] : j.items()) {
        if (value.is_string()) hello_map[key] = value.get<std::string>();
    }
    const auto pinfo = register_peer_from_hello(hello_map, endpoint);
    if (!pinfo) co_return; // route gate or malformed identity
    try { save_known_peers(); } catch (const std::exception&) {}

    const bool response_flag = j.value("response", false);
    const bool have_address = !endpoint.address().is_unspecified();

    if (!response_flag && have_address) {
        // Answer the contact with our signed identity (main.py HELLO reply).
        try {
            const auto wire = build_signed_hello(*this, true).dump();
            send_outer_frame(*this, HELLO_FRAME, wire, endpoint);
        } catch (const std::exception& error) {
            std::cerr << "HELLO response to " << endpoint << " failed: " << error.what() << "\n";
        }
    }

    // Deterministic initiator: the lexicographically smaller identity drives
    // S1/S2, so exactly one side initiates even when both nodes bootstrap each
    // other at startup. Re-initiation is skipped while a session or an in-
    // flight handshake with this peer already exists.
    const bool i_am_initiator = my_id_.has_value() && *my_id_ < *peer_id;
    if (!i_am_initiator || !have_address) co_return;

    {
        const auto session_it = sessions_by_peer_id.find(*peer_id);
        if (session_it != sessions_by_peer_id.end() && session_it->second &&
            session_it->second->state == SessionState::ESTABLISHED) {
            co_return;
        }
        for (const auto& [sid, pending] : pending_handshakes_) {
            if (pending.peer_id == *peer_id) co_return; // in flight
        }
    }

    if (!initiate_handshake(*peer_id, endpoint)) {
        std::cerr << "handshake initiation toward " << endpoint << " failed\n";
    }
}

bool PQVPNNode::initiate_handshake(
    const std::vector<uint8_t>& peer_id, const asio::ip::udp::endpoint& endpoint) {
    if (!my_id_.has_value() || *my_id_ == peer_id) return false;
    if (endpoint.address().is_unspecified()) return false;

    const auto keys = peer_hybrid_keys(peer_id);
    if (!keys) {
        std::cerr << "cannot initiate handshake: no hybrid keys registered for peer\n";
        return false;
    }
    const auto& [peer_x25519_pk, peer_ml_kem_pk] = *keys;

    try {
        // Ephemeral X25519 half (PFS) + ML-KEM-1024 encapsulation against the
        // peer's advertised long-term KEM key.
        const auto ephemeral = crypto::X25519::keygen();
        const auto kem = crypto::KEM::encaps(peer_ml_kem_pk);
        const auto x25519_secret = crypto::X25519::derive(ephemeral.private_key, peer_x25519_pk);

        const auto session_id = random_bytes(8);
        nlohmann::json s1 = {
            {"peerid", hex_id(*my_id_)},
            {"sessionid", hex_id(session_id)},
            {"ct", hex_id(kem.ciphertext)},
            {"x25519_pk", hex_id(ephemeral.public_key)},
            {"ed25519_pk", hex_id(ed25519_public_key)},
            {"mldsa_pk", hex_id(ml_dsa_public_key)},
            {"timestamp", static_cast<long long>(now_seconds())}
        };
        const auto [ed_sig, mld_sig] = sign_hybrid_message(
            ed25519_private_key, ml_dsa_private_key,
            canonical_json(s1, kS1Fields));
        s1["ed25519_sig"] = ed_sig;
        s1["mldsa_sig"] = mld_sig;

        const std::string wire = s1.dump();
        if (!send_outer_frame(*this, S1_FRAME, wire, endpoint)) return false;

        pending_handshakes_[hex_id(session_id)] = PendingHandshake{
            peer_id,
            endpoint,
            ephemeral.private_key,
            kem.shared_secret,
            std::vector<uint8_t>(wire.begin(), wire.end()),
            now_seconds()};
    } catch (const std::exception& error) {
        std::cerr << "handshake initiation failed for " << endpoint << ": " << error.what() << "\n";
        return false;
    }

    std::cout << "S1 sent to " << endpoint << " (handshake initiated)\n";
    const bool handshake_started = true;
    return handshake_started;
}

asio::awaitable<void> PQVPNNode::handle_s1_frame(
    std::vector<uint8_t> payload, const asio::ip::udp::endpoint& endpoint) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(payload);
    } catch (const std::exception&) {
        co_return;
    }
    if (!j.is_object()) co_return;

    if (!verify_hybrid_signatures(j, kS1Fields)) {
        std::cerr << "rejecting S1 from " << endpoint
                  << ": hybrid signature verification failed\n";
        co_return;
    }

    const auto peer_id = hex_field(j, "peerid");
    const auto session_id = hex_field(j, "sessionid");
    const auto ciphertext = hex_field(j, "ct");
    const auto eph_pk = hex_field(j, "x25519_pk");
    if (!peer_id || peer_id->empty() || !session_id || session_id->size() != 8 ||
        !ciphertext || ciphertext->empty() || !eph_pk || eph_pk->size() != 32) {
        co_return;
    }
    if (my_id_.has_value() && *peer_id == *my_id_) co_return;
    if (!is_peer_allowed(*peer_id)) co_return;

    // TOFU consistency: an identity already known with different auth keys is
    // an impersonation attempt — reject before any key material moves.
    const auto known = known_peers_.find(hex_id(*peer_id));
    if (known != known_peers_.end()) {
        for (const char* name : {"ed25519_pk", "mldsa_pk"}) {
            const auto stored = known->second.find(name);
            if (stored != known->second.end() && !stored->second.empty() &&
                stored->second != j.value(name, std::string{})) {
                std::cerr << "rejecting S1 from " << endpoint
                          << ": identity key mismatch for " << name << "\n";
                co_return;
            }
        }
    }

    // Decapsulate the ML-KEM ciphertext and derive the classical half against
    // our long-term X25519 key. The transcript is the raw S1 payload exactly as
    // received, so both sides bind identical bytes.
    std::vector<uint8_t> x25519_secret;
    std::vector<uint8_t> ml_kem_secret;
    try {
        ml_kem_secret = crypto::KEM::decaps(*ciphertext, ml_kem_secret_key);
        x25519_secret = crypto::X25519::derive(x25519_private_key, *eph_pk);
    } catch (const std::exception& error) {
        std::cerr << "S1 key derivation failed from " << endpoint << ": " << error.what() << "\n";
        co_return;
    }

    auto session = std::shared_ptr<Session>();
    try {
        session = establish_hybrid_session(
            *peer_id, endpoint, x25519_secret, ml_kem_secret, payload, /*initiator=*/false);
    } catch (const std::exception& error) {
        std::cerr << "S1 session establishment failed for " << endpoint << ": " << error.what() << "\n";
        co_return;
    }
    if (!session) co_return; // route gate refused the peer address

    std::cout << "Session established (responder) with " << endpoint
              << " id=" << hex_id(session->session_id).substr(0, 8) << "\n";

    // Confirm to the initiator: signed S2 carrying our long-term X25519 key so
    // it can derive the classical half and cross-check it against what its
    // HELLO exchange registered for us.
    try {
        nlohmann::json s2 = {
            {"peerid", my_id_.has_value() ? hex_id(*my_id_) : std::string{}},
            {"sessionid", j.value("sessionid", std::string{})},
            {"ed25519_pk", hex_id(ed25519_public_key)},
            {"mldsa_pk", hex_id(ml_dsa_public_key)},
            {"x25519_pk", hex_id(x25519_public_key)},
            {"timestamp", static_cast<long long>(now_seconds())}
        };
        const auto [ed_sig, mld_sig] = sign_hybrid_message(
            ed25519_private_key, ml_dsa_private_key,
            canonical_json(s2, kS2Fields));
        s2["ed25519_sig"] = ed_sig;
        s2["mldsa_sig"] = mld_sig;
        send_outer_frame(*this, S2_FRAME, s2.dump(), endpoint);
    } catch (const std::exception& error) {
        std::cerr << "S2 to " << endpoint << " failed: " << error.what() << "\n";
    }
}

asio::awaitable<void> PQVPNNode::handle_s2_frame(
    std::vector<uint8_t> payload, const asio::ip::udp::endpoint& endpoint) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(payload);
    } catch (const std::exception&) {
        co_return;
    }
    if (!j.is_object()) co_return;

    const auto session_id_hex = j.value("sessionid", std::string{});
    const auto pending_it = pending_handshakes_.find(session_id_hex);
    if (pending_it == pending_handshakes_.end()) co_return; // unknown/expired
    const auto& pending = pending_it->second;

    // Bind the confirmation to the peer and address we initiated toward.
    const auto peer_id = hex_field(j, "peerid");
    if (!peer_id || *peer_id != pending.peer_id) co_return;
    if (endpoint.address().is_unspecified() || endpoint != pending.endpoint) co_return;

    if (!verify_hybrid_signatures(j, kS2Fields)) {
        std::cerr << "rejecting S2 from " << endpoint
                  << ": hybrid signature verification failed\n";
        co_return;
    }

    // Cross-check the responder's long-term X25519 key against what its signed
    // HELLO registered (TOFU): a mismatch means the confirmation does not come
    // from the identity we contacted.
    const auto s2_x25519_pk = hex_field(j, "x25519_pk");
    if (!s2_x25519_pk || s2_x25519_pk->size() != 32) co_return;
    const auto registered = peer_hybrid_keys(pending.peer_id);
    if (!registered || registered->first != *s2_x25519_pk) {
        std::cerr << "rejecting S2 from " << endpoint
                  << ": x25519 key does not match HELLO registration\n";
        co_return;
    }

    std::vector<uint8_t> x25519_secret;
    try {
        x25519_secret = crypto::X25519::derive(pending.x25519_ephemeral_sk, *s2_x25519_pk);
    } catch (const std::exception& error) {
        std::cerr << "S2 key derivation failed for " << endpoint << ": " << error.what() << "\n";
        co_return;
    }

    auto session = std::shared_ptr<Session>();
    try {
        session = establish_hybrid_session(
            pending.peer_id, pending.endpoint,
            x25519_secret, pending.ml_kem_secret, pending.transcript,
            /*initiator=*/true);
    } catch (const std::exception& error) {
        std::cerr << "S2 session establishment failed for " << endpoint << ": " << error.what() << "\n";
        co_return;
    }
    if (!session) co_return;

    pending_handshakes_.erase(pending_it);
    std::cout << "Session established (initiator) with " << endpoint
              << " id=" << hex_id(session->session_id).substr(0, 8) << "\n";
}

asio::awaitable<void> PQVPNNode::bootstrap_peers(
    std::vector<asio::ip::udp::endpoint> peers) {
    if (peers.empty()) co_return;
    std::cout << "Bootstrap contact loop started for " << peers.size() << " peer(s)\n";

    while (true) {
        for (const auto& endpoint : peers) {
            bool established = false;
            for (const auto& [peer_id, session] : sessions_by_peer_id) {
                if (session && session->state == SessionState::ESTABLISHED &&
                    session->remote_addr == endpoint) {
                    established = true;
                    break;
                }
            }
            if (established) continue; // session live: nothing to contact

            try {
                const auto wire = build_signed_hello(*this, /*response=*/false).dump();
                send_outer_frame(*this, HELLO_FRAME, wire, endpoint);
            } catch (const std::exception& error) {
                std::cerr << "bootstrap HELLO to " << endpoint << " failed: " << error.what() << "\n";
            }
        }

        asio::steady_timer timer(co_await asio::this_coro::executor);
        timer.expires_after(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::duration<double>(bootstrap_retry_interval)));
        try {
            co_await timer.async_wait(asio::use_awaitable);
        } catch (const asio::system_error&) {
            co_return; // io_context stopped: shutdown in progress
        }
    }
}

// Legacy UDPProtocol dispatch carries no sender address: verify and register
// only — replying or initiating needs the peer's endpoint, which this path
// cannot know. The runtime uses handle_hello_frame with the real endpoint.
asio::awaitable<void> PQVPNNode::handle_hello(
    std::vector<uint8_t> payload,
    const std::map<std::string, std::string>& extra_info,
    const std::vector<uint8_t>& signature,
    uint64_t nonce) {
    (void)extra_info;
    (void)signature;
    (void)nonce;
    co_await handle_hello_frame(std::move(payload), asio::ip::udp::endpoint());
}
