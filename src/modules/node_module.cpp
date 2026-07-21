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
#include <optional>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <vector>
#include <nlohmann/json.hpp>
#include "hybrid_kdf.hpp"

using namespace pqvpn;
using namespace std::chrono_literals;

namespace {

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

std::vector<uint8_t> encrypt_layer(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv) {
    const EVP_CIPHER* cipher = key.size() == 16 ? EVP_aes_128_gcm() :
        key.size() == 32 ? EVP_aes_256_gcm() : nullptr;
    if (!cipher || iv.size() != 12) throw std::invalid_argument("onion session has invalid AEAD material");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) throw std::runtime_error("AEAD context allocation failed");
    std::vector<uint8_t> output(plaintext.size() + 16);
    int written = 0;
    int final_written = 0;
    if (EVP_EncryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), iv.data()) != 1 ||
        EVP_EncryptUpdate(context.get(), output.data(), &written, plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(context.get(), output.data() + written, &final_written) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, 16, output.data() + written + final_written) != 1) {
        throw std::runtime_error("onion AEAD encryption failed");
    }
    output.resize(written + final_written + 16);
    return output;
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

    const auto peer_hex = hex_id(peer.peer_id);
    mesh.peers[peer_hex] = peer;

    auto& known = known_peers_[peer_hex];
    known["nickname"] = peer.nickname;
    known["ed25519_pk"] = hello.contains("ed25519_pk") ? hello.at("ed25519_pk") : "";
    known["brainpoolP512r1_pk"] = hello.contains("brainpoolP512r1_pk") ? hello.at("brainpoolP512r1_pk") : "";
    known["kyber_pk"] = hello.contains("kyber_pk") ? hello.at("kyber_pk") : "";
    known["mldsa_pk"] = hello.contains("mldsa_pk") ? hello.at("mldsa_pk") : "";
    known["is_relay"] = peer.is_relay ? "true" : "false";

    return peer;
}

asio::awaitable<void> PQVPNNode::session_maintenance() {
    std::cout << "Session maintenance task started" << std::endl;
    try {
        while (true) {
            try {
                int active = 0;
                for (auto it = sessions_by_peer_id.begin(); it != sessions_by_peer_id.end();) {
                    auto& sess = *(it->second);
                    const double now = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count();

                    if (now - sess.last_activity > SESSION_TIMEOUT) {
                        std::cout << "Pruning stale session " << hex_id(sess.session_id).substr(0, 8) << std::endl;
                        it = sessions_by_peer_id.erase(it);
                        continue;
                    }

                    if (sess.state == SessionState::ESTABLISHED) {
                        ++active;
                        try {
                            std::ostringstream oss;
                            oss << "{\"type\":\"heartbeat\",\"sessionid\":\"";
                            oss << hex_id(sess.session_id);
                            oss << "\",\"timestamp\":" << static_cast<long long>(now) << ",";
                            oss << "\"peerid\":\"" << (my_id_.has_value() ? hex_id(*my_id_) : "") << "\",";
                            oss << "\"uptime\":0}";
                            std::string heartbeat_str = oss.str();
                            auto hb = std::vector<uint8_t>(heartbeat_str.begin(), heartbeat_str.end());
                            const auto peer_for_hash = sess.peer_id_.value_or(sess.session_id);
                            auto frame = make_outer_frame(4, peer_hash8(peer_for_hash), 0, hb);
                            if (transport && !sess.remote_addr.address().is_unspecified()) {
                                transport->send_to(asio::buffer(frame), sess.remote_addr);
                            }
                        } catch (...) {
                        }

                        try {
                            const auto rekey_it = rekey_manager.last_rekey.find(sess.session_id);
                            const double last_rekey = rekey_it != rekey_manager.last_rekey.end()
                                ? rekey_it->second : sess.created_at;
                            if (rekey_manager.should_rekey(sess.session_id, sess.bytes_sent + sess.bytes_recv, last_rekey)) {
                                try {
                                    auto [sid, aead_send, aead_recv] = rekey_manager.perform_rekey(sess.session_id);
                                    (void)sid;
                                    sess.aead_send_key = std::move(aead_send);
                                    sess.aead_recv_key = std::move(aead_recv);
                                    sess.session_iv.clear();
                                    sess.last_activity = now;
                                } catch (const std::exception& e) {
                                    std::cerr << "Rekey failed: " << e.what() << std::endl;
                                }
                            }
                        } catch (...) {
                        }
                    }
                    ++it;
                }
                std::cout << "Session maintenance: active_sessions=" << active << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "session_maintenance loop error: " << e.what() << std::endl;
            }
            asio::steady_timer timer(co_await asio::this_coro::executor);
            timer.expires_after(std::chrono::seconds(static_cast<int>(KEEPALIVE_INTERVAL)));
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

asio::awaitable<void> PQVPNNode::datagram_received(
    std::vector<uint8_t> data,
    asio::ip::udp::endpoint endpoint) {
    (void)endpoint;
    if (data.size() < 16 || data[0] != 1) {
        co_return;
    }

    const auto payload_size = static_cast<std::size_t>(
        (static_cast<uint16_t>(data[14]) << 8) | data[15]);
    if (payload_size != data.size() - 16) {
        co_return;
    }
    co_return;
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

bool PQVPNNode::is_peer_allowed(const std::vector<uint8_t>& peer_id) const {
    const auto identity = hex_id(peer_id);
    if (!allowlist_.empty()) return allowlist_.contains(identity);
    const bool previously_known = known_peers_.contains(identity);
    return previously_known || tofu_enabled_;
}

bool PQVPNNode::check_and_record_nonce(Session& session, const std::vector<uint8_t>& nonce) const {
    if (nonce.size() != 12) return false;
    const std::array<uint8_t, 4> expected_prefix = session.session_iv.size() >= 4
        ? std::array<uint8_t, 4>{session.session_iv[0], session.session_iv[1], session.session_iv[2], session.session_iv[3]}
        : std::array<uint8_t, 4>{0, 0, 0, 0};
    if (!std::equal(expected_prefix.begin(), expected_prefix.end(), nonce.begin())) return false;
    uint64_t counter = 0;
    for (std::size_t index = 4; index < nonce.size(); ++index) {
        counter = (counter << 8) | nonce[index];
    }
    if (counter <= session.nonce_recv || session.replay_window.contains(counter)) return false;
    session.nonce_recv = counter;
    session.replay_window.insert(counter);
    while (session.replay_window.size() > session.replay_window_size) {
        session.replay_window.erase(session.replay_window.begin());
    }
    return session.replay_window.contains(counter);
}

std::vector<uint8_t> PQVPNNode::make_outer_frame(
    const uint8_t frame_type,
    const std::vector<uint8_t>& hop_id,
    const uint32_t circuit_id,
    const std::vector<uint8_t>& payload) const {
    return encode_outer_frame(frame_type, hop_id, circuit_id, payload);
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
    if (path.empty()) return std::nullopt;
    std::vector<uint8_t> layer = inner_frame;
    bool encrypted = false;
    for (auto hop = path.rbegin(); hop != path.rend(); ++hop) {
        const auto session = sessions_by_peer_id.find(*hop);
        if (session == sessions_by_peer_id.end() || !session->second) continue;
        layer = encrypt_layer(layer, session->second->aead_send_key, session->second->session_iv);
        layer = encode_outer_frame(3, peer_hash8(*hop), circuit_id, layer);
        encrypted = true;
    }
    if (!encrypted) return std::nullopt;
    return layer;
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
    session->created_at = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    session->last_activity = session->created_at;
    sessions_by_peer_id[peer_id] = session;
    return session;
}

asio::awaitable<bool> PQVPNNode::send_onion(
    const std::vector<std::vector<uint8_t>>& path,
    const std::vector<uint8_t>& inner_frame) {
    const auto frame = build_onion_frame(path, inner_frame);
    if (!frame || path.empty() || !transport) co_return false;
    const auto session = sessions_by_peer_id.find(path.back());
    if (session == sessions_by_peer_id.end() || !session->second ||
        session->second->remote_addr.address().is_unspecified()) co_return false;
    asio::error_code error;
    transport->send_to(asio::buffer(*frame), session->second->remote_addr, 0, error);
    co_return !error;
}
