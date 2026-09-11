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

std::vector<uint8_t> tunnel_nonce(const std::vector<uint8_t>& iv, const uint64_t counter) {
    if (iv.size() != 12 || counter == 0) {
        throw std::invalid_argument("tunnel session has invalid nonce state");
    }
    std::vector<uint8_t> nonce(12);
    std::copy_n(iv.begin(), 4, nonce.begin());
    for (std::size_t index = 0; index < 8; ++index) {
        nonce[4 + index] = static_cast<uint8_t>(counter >> (56 - index * 8));
    }
    return nonce;
}

std::vector<uint8_t> tunnel_encrypt(
    const std::span<const uint8_t> plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::span<const uint8_t> aad) {
    const EVP_CIPHER* cipher = key.size() == 16 ? EVP_aes_128_gcm() :
        key.size() == 32 ? EVP_aes_256_gcm() : nullptr;
    if (!cipher || nonce.size() != 12) throw std::invalid_argument("invalid tunnel AEAD material");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) throw std::runtime_error("tunnel AEAD context allocation failed");

    std::vector<uint8_t> output(plaintext.size() + 16);
    int ignored = 0;
    int written = 0;
    int final_written = 0;
    if (EVP_EncryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_EncryptUpdate(context.get(), nullptr, &ignored, aad.data(), static_cast<int>(aad.size())) != 1 ||
        EVP_EncryptUpdate(context.get(), output.data(), &written, plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(context.get(), output.data() + written, &final_written) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, 16, output.data() + written + final_written) != 1) {
        throw std::runtime_error("tunnel AEAD encryption failed");
    }
    output.resize(static_cast<std::size_t>(written + final_written) + 16);
    return output;
}

std::optional<std::vector<uint8_t>> tunnel_decrypt(
    const std::span<const uint8_t> ciphertext_and_tag,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::span<const uint8_t> aad) {
    if (ciphertext_and_tag.size() < 16) return std::nullopt;
    const EVP_CIPHER* cipher = key.size() == 16 ? EVP_aes_128_gcm() :
        key.size() == 32 ? EVP_aes_256_gcm() : nullptr;
    if (!cipher || nonce.size() != 12) return std::nullopt;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) return std::nullopt;

    const auto ciphertext_size = ciphertext_and_tag.size() - 16;
    std::vector<uint8_t> plaintext(ciphertext_size);
    int ignored = 0;
    int written = 0;
    int final_written = 0;
    if (EVP_DecryptInit_ex(context.get(), cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &ignored, aad.data(), static_cast<int>(aad.size())) != 1 ||
        EVP_DecryptUpdate(context.get(), plaintext.data(), &written, ciphertext_and_tag.data(), static_cast<int>(ciphertext_size)) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, 16,
            const_cast<uint8_t*>(ciphertext_and_tag.data() + ciphertext_size)) != 1 ||
        EVP_DecryptFinal_ex(context.get(), plaintext.data() + written, &final_written) != 1) {
        return std::nullopt;
    }
    plaintext.resize(static_cast<std::size_t>(written + final_written));
    return plaintext;
}

// Blocking socket sends executed inside coroutine frames are unreliable on
// some MinGW/Asio combinations: the datagram is dropped while the call still
// reports success (verified with loopback probes). Perform the send in a
// posted non-coroutine handler and co_await its result instead.
asio::awaitable<bool> post_udp_send(
    asio::io_context& io,
    asio::ip::udp::socket* transport,
    std::shared_ptr<std::vector<uint8_t>> payload,
    const asio::ip::udp::endpoint& endpoint) {
    if (!transport || !payload) co_return false;

    auto ok = std::make_shared<bool>(false);
    // A far-future timer used purely as a one-shot resume signal: the posted
    // handler cancels it once the send has completed.
    asio::steady_timer signal(io, (std::numeric_limits<std::chrono::nanoseconds>::max)());
    asio::post(io, [transport, payload, endpoint, ok, &signal]() {
        asio::error_code error;
        transport->send_to(asio::buffer(*payload), endpoint, 0, error);
        *ok = !error;
        signal.cancel();
    });
    try {
        co_await signal.async_wait(asio::use_awaitable);
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
    if (data.size() < 16 || data[0] != 1) {
        co_return;
    }

    const auto payload_size = static_cast<std::size_t>(
        (static_cast<uint16_t>(data[14]) << 8) | data[15]);
    if (payload_size != data.size() - 16) {
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
            outer_next_hash, circuit_id);
        co_return;
    }

    if (data[1] != TUNNEL_DATA_FRAME || payload_size < 28) {
        co_return;
    }

    const std::vector<uint8_t> session_hint(data.begin() + 2, data.begin() + 10);
    std::shared_ptr<Session> session;
    for (const auto& [peer_id, candidate] : sessions_by_peer_id) {
        (void)peer_id;
        if (!candidate || candidate->state != SessionState::ESTABLISHED ||
            candidate->remote_addr != endpoint || candidate->session_id.size() < session_hint.size()) {
            continue;
        }
        if (std::equal(session_hint.begin(), session_hint.end(), candidate->session_id.begin())) {
            if (session) co_return; // Ambiguous truncated session identifier.
            session = candidate;
        }
    }
    if (!session || session->aead_recv_key.empty() || session->session_iv.size() != 12) {
        co_return;
    }

    const std::vector<uint8_t> nonce(data.begin() + 16, data.begin() + 28);
    const auto plaintext = tunnel_decrypt(
        std::span<const uint8_t>(data).subspan(28),
        session->aead_recv_key,
        nonce,
        std::span<const uint8_t>(data).first(16));
    if (!plaintext || plaintext->empty() || !check_and_record_nonce(*session, nonce)) {
        co_return;
    }

    session->bytes_recv += plaintext->size();
    session->last_activity = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (tunnel_packet_handler_) tunnel_packet_handler_(*plaintext);
    co_return;
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
    session.last_activity = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
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
    const std::vector<uint8_t>* best = nullptr;
    double best_activity = 0.0;
    for (const auto& [peer_id, session] : sessions_by_peer_id) {
        if (!session || session->state != SessionState::ESTABLISHED) continue;
        if (session->remote_addr.address().is_unspecified()) continue;
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
    const auto peer = select_tunnel_peer();
    if (!peer) co_return false;
    const auto datagram = build_tunnel_datagram(*peer, std::span<const uint8_t>(packet));
    if (!datagram) co_return false;
    const auto found = sessions_by_peer_id.find(*peer);
    if (found == sessions_by_peer_id.end() || !found->second ||
        found->second->remote_addr.address().is_unspecified()) {
        co_return false;
    }
    // Posted send on the io_context: the adapter reader thread must not touch
    // the Asio socket directly (see post_udp_send).
    auto payload = std::make_shared<std::vector<uint8_t>>(std::move(*datagram));
    const auto endpoint = found->second->remote_addr;
    co_return co_await post_udp_send(io_context_, transport, std::move(payload), endpoint);
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
        const auto found = sessions_by_peer_id.find(hop);
        if (found == sessions_by_peer_id.end() || !found->second) return std::nullopt;
        auto& session = *found->second;
        if ((session.aead_send_key.size() != 16 && session.aead_send_key.size() != 32) ||
            session.session_iv.size() != 12 || session.session_id.size() < 8 ||
            session.nonce_send == std::numeric_limits<uint64_t>::max()) {
            return std::nullopt;
        }

        const auto next_hash = peer_hash8(target);
        // AAD: "PQVPN" + full session id + identity hash of the peeling hop +
        // circuit id (BE). main.py bound the *target* hash here, which its own
        // handle_relay could not reproduce; binding the peeler is the minimal
        // self-consistent reading of the same four-part AAD.
        std::vector<uint8_t> aad{'P', 'Q', 'V', 'P', 'N'};
        aad.insert(aad.end(), session.session_id.begin(), session.session_id.end());
        const auto peeler_hash = peer_hash8(hop);
        aad.insert(aad.end(), peeler_hash.begin(), peeler_hash.end());
        for (int shift = 24; shift >= 0; shift -= 8) {
            aad.push_back(static_cast<uint8_t>((circuit_id >> shift) & 0xff));
        }

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
    // The outer frame is addressed to the first hop (main.py send_onion).
    const auto session = sessions_by_peer_id.find(path[0]);
    if (session == sessions_by_peer_id.end() || !session->second ||
        session->second->remote_addr.address().is_unspecified()) co_return false;

    const auto frame_size = frame->size();
    auto payload = std::make_shared<std::vector<uint8_t>>(std::move(*frame));
    const auto endpoint = session->second->remote_addr;
    const bool sent = co_await post_udp_send(io_context_, transport, std::move(payload), endpoint);
    if (sent) {
        session->second->bytes_sent += frame_size;
        session->second->last_activity = std::chrono::duration<double>(
            std::chrono::system_clock::now().time_since_epoch()).count();
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

// Builds the four-part relay AAD: "PQVPN" + full session id + 8-byte identity
// hash of the node that peels this layer + circuit id (big-endian).
std::vector<uint8_t> relay_aad(
    const std::vector<uint8_t>& session_id,
    const std::vector<uint8_t>& peeler_hash,
    uint32_t circuit_id) {
    std::vector<uint8_t> aad{'P', 'Q', 'V', 'P', 'N'};
    aad.insert(aad.end(), session_id.begin(), session_id.end());
    aad.insert(aad.end(), peeler_hash.begin(), peeler_hash.end());
    for (int shift = 24; shift >= 0; shift -= 8) {
        aad.push_back(static_cast<uint8_t>((circuit_id >> shift) & 0xff));
    }
    return aad;
}

} // namespace

asio::awaitable<bool> PQVPNNode::handle_relay(
    const std::vector<uint8_t>& session_hint,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext_and_tag,
    const std::vector<uint8_t>& outer_next_hash,
    uint32_t circuit_id) {
    // main.py handle_relay: decrypt one onion layer and either forward the
    // inner content to the next hop or deliver it locally.
    auto session = find_session_by_hint(sessions_by_peer_id, session_hint);
    if (!session || !*session) co_return false;
    auto& sess = **session;

    // A relay must know its own identity: it binds the layer AAD and decides
    // local delivery (main.py: nexth == peer_hash8(my_id)).
    if (!my_id_.has_value()) co_return false;
    const auto self_hash = peer_hash8(*my_id_);

    // The outer header's next-hop field must identify this node for the layer
    // it peels; the builder binds the same value into the AAD.
    if (outer_next_hash != self_hash) co_return false;

    const auto aad = relay_aad(sess.session_id, self_hash, circuit_id);
    const auto plaintext = tunnel_decrypt(
        std::span<const uint8_t>(ciphertext_and_tag), sess.aead_recv_key, nonce,
        std::span<const uint8_t>(aad));
    if (!plaintext || plaintext->size() < 9) co_return false; // nexth(8) + >=1 content byte

    // Replay defense: monotonic counter with bounded window (main.py parity).
    // Recorded only after authentication succeeds, so an invalid-tag packet
    // cannot advance the replay window and evict a legitimate nonce (same
    // order as the tunnel data path in datagram_received).
    if (!check_and_record_nonce(sess, nonce)) co_return false;

    const auto next_hash = std::vector<uint8_t>(plaintext->begin(), plaintext->begin() + 8);
    const auto inner_frame = std::vector<uint8_t>(plaintext->begin() + 8, plaintext->end());

    sess.bytes_recv += ciphertext_and_tag.size();
    sess.last_activity = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();

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
        if (!check_and_record_nonce(data_sess, data_nonce)) co_return false;

        tunnel_packet_handler_(*packet);
        data_sess.bytes_recv += body.size();
        co_return true;
    }

    // Forward the peeled content as-is to the next hop (main.py parity: first
    // peer whose identity hash matches).
    std::shared_ptr<Session> target;
    for (const auto& [peer_id, candidate] : sessions_by_peer_id) {
        if (!candidate || candidate->state != SessionState::ESTABLISHED) continue;
        if (peer_hash8(peer_id) == next_hash && !target) target = candidate;
    }
    if (!target || target->remote_addr.address().is_unspecified() || !transport) {
        co_return false;
    }

    const auto frame_size = inner_frame.size();
    auto payload = std::make_shared<std::vector<uint8_t>>(std::move(inner_frame));
    const auto endpoint = target->remote_addr;
    if (!co_await post_udp_send(io_context_, transport, std::move(payload), endpoint)) {
        co_return false;
    }

    target->bytes_sent += frame_size;
    target->last_activity = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    co_return true;
}
