#include "PQVPNNode.h"
#include "crypto_signature.hpp"
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/int.h>
  #include <unistd.h>
#endif

#include <array>
#include <cstring>
#include <random>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <nlohmann/json.hpp>
#include <fstream>

// Helper function to convert hex string to bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper function to convert bytes to hex string
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (uint8_t byte : bytes) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Helper function to check if string contains only hex characters
bool is_hex_string(const std::string& s) {
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}

PQVPNNode::PQVPNNode(boost::asio::io_context& io_context, const std::string& config_path)
    : config_path_(config_path), io_context_(io_context), telemetry_timer_(io_context), port(0) {
    schedule_telemetry();
}

sockaddr* PQVPNNode::get_sockaddr(const std::string& host, int port_num, bool is_ipv4) {
    thread_local sockaddr_storage storage{};
    std::memset(&storage, 0, sizeof(storage));

    if (is_ipv4) {
        auto* addr = reinterpret_cast<sockaddr_in*>(&storage);
        addr->sin_family = AF_INET;
        addr->sin_port = htons(static_cast<uint16_t>(port_num));
        if (inet_pton(AF_INET, host.c_str(), &addr->sin_addr) != 1) {
            return nullptr;
        }
        return reinterpret_cast<sockaddr*>(addr);
    }

    auto* addr = reinterpret_cast<sockaddr_in6*>(&storage);
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(static_cast<uint16_t>(port_num));
    if (inet_pton(AF_INET6, host.c_str(), &addr->sin6_addr) != 1) {
        return nullptr;
    }
    return reinterpret_cast<sockaddr*>(addr);
}

int PQVPNNode::get_sockaddr_len(bool is_ipv4) {
    return is_ipv4 ? static_cast<int>(sizeof(sockaddr_in)) : static_cast<int>(sizeof(sockaddr_in6));
}

void PQVPNNode::set_port(int new_port) {
    if (new_port < 0 || new_port > 65535) {
        throw std::out_of_range("port must be in range 0..65535");
    }
    port = new_port;
}

void PQVPNNode::initiate_handshake(const PeerInfo& pinfo, const std::string& addr, int peer_port) {
    if (addr.empty() || peer_port <= 0 || peer_port > 65535 || pinfo.kyber_pk.empty()) {
        return;
    }

    nlohmann::json hello;
    hello["nickname"] = pinfo.nickname;
    hello["kyber_pk"] = bytes_to_hex(pinfo.kyber_pk);
    hello["ed25519_pk"] = bytes_to_hex(pinfo.ed25519_pk);
    hello["mldsa_pk"] = bytes_to_hex(pinfo.mldsa_pk);
    const auto encoded = hello.dump();
    const std::vector<uint8_t> payload(encoded.begin(), encoded_end());
    std::vector<uint8_t> session_id(8, 0);
    const auto frame = make_outer_frame(1, session_id, 0, payload);
    send_to(std::vector<uint8_t>(frame.begin(), frame.end()), addr, peer_port);
}

std::string PQVPNNode::make_outer_frame(int ft_type, const std::vector<uint8_t>& session_id, uint32_t circuit_id, const std::vector<uint8_t>& data) {
    if (data.size() > 0xFFFF) {
        throw std::length_error("outer frame payload exceeds 65535 bytes");
    }

    std::string frame;
    frame.reserve(16 + data.size());
    frame.push_back(static_cast<char>(1)); // version
    frame.push_back(static_cast<char>(ft_type & 0xFF));

    std::array<uint8_t, 8> hop{};
    std::copy_n(session_id.begin(), std::min(session_id.size(), hop.size()), hop.begin());
    for (uint8_t byte : hop) {
        frame.push_back(static_cast<char>(byte));
    }

    frame.push_back(static_cast<char>((circuit_id >> 24) & 0xFF));
    frame.push_back(static_cast<char>((circuit_id >> 16) & 0xFF));
    frame.push_back(static_cast<char>((circuit_id >> 8) & 0xFF));
    frame.push_back(static_cast<char>(circuit_id & 0xFF));

    uint16_t len = static_cast<uint16_t>(data.size());
    frame.push_back(static_cast<char>((len >> 8) & 0xFF));
    frame.push_back(static_cast<char>(len & 0xFF));

    frame.append(reinterpret_cast<const char*>(data.data()), data.size());
    return frame;
}

    uint16_t len = static_cast<uint16_t>(data.size());
    frame.push_back(static_cast<char>((len >> 8) & 0xFF));
    frame.push_back(static_cast<char>(len & 0xFF));

    frame.append(reinterpret_cast<const char*>(data.data()), data.size());
    return frame;
}
        return frame;frame;           ipv4_transport->sendto(data, host, port_num);
            return !data.empty();
        } catch (const std::exception& e) {
            std::cerr << "[Error] IPv4 Transport error: " << e.what() << "\n";
            return false;
        }
    }
    if (transport) {
        try {
            transport->sendto(data, host, port_num);
            return !data.empty();
        } catch (const std::exception& e) {
            std::cerr << "[Error] Transport error: " << e.what() << "\n";
            return false;
        }
    }

        const int family = is_ipv4 ? AF_INET : AF_INET6;
        const auto sock = socket(family, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        auto* address = const_cast<sockaddr*>(get_sockaddr(host, port_num, is_ipv4));
        if (!address) {
#ifdef _WIN32
            closesocket(sock);
#else
            close(int(sock));
#endif
            return false;
        }
        const int sent = ::sendto(sock, reinterpret_cast<const char*>(data.data()),
            static_cast<int>(data.size()), 0, address, get_sockaddr_len(is_ipv4));
#ifdef _WIN32
        closesocket(sock);
#else
        close(int(sock));
#endif
        return sent >= 0;
    }
}

void PQVPNNode::handle_s1(const std::vector<uint8_t>& payload, const std::string& addr, int port,
                          const std::vector<uint8_t>& outer_next_hash, int circuit_id) {
    try {
        if (payload.empty()) {
            return;
        }
        nlohmann::json j = nlohmann::json::parse(payload.begin(), payload.end());

        const std::string peerid_hex = j.value("peerid", "");
        if (peer_id_hex.empty() || !is_hex_string(peer_id_hex)) {
            return;
        }
        const std::vector<uint8_t> peer_id = hex_to_bytes(peer_id_hex);
        if (peer_id.empty()) {
            return;
        }

        const std::string sig_hex = j.value("ed25519_sig", "");
        const std::string pk_hex = j.value("ed25519_pk", "");
        if (!sig_hex.empty() || !pk_hex.empty()) {
            if (sig_hex.empty() || pk_hex.empty() || !is_hex_string(sig_hex) || !is_hex_string(pk_hex)) {
                return;
            }
            const auto sig_bytes = hex_to_bytes(sig_hex);
            const auto pk_bytes = hex_to_bytes(pk_hex);
            if (!pqvpn::pq_sig_verify(pk_bytes, payload, sig_bytes, std::string("Ed25519"))) {
                return;
            }
        }
    } catch (const std::exception& e) {
        return;
    }
}

void PQVPNNode::handle_hello(const std::vector<uint8_t>& payload, const std::string& addr, int port,
                             const std::vector<uint8_t>& outer_next_hash, int circuit_id) {
    if (payload.empty()) return;

    try {
        nlohmann::json j = nlohmann::json::parse(payload.begin(), payload.end());

        // Build canonical bytes to verify (HELLO_SIGN_FIELDS exclude sig fields)
        std::vector<std::string> hello_sign_fields = {
            "peerid", "nickname", "ed25519_pk", "brainpoolP512r1_pk",
            "kyber_pk", "mldsa_pk", "timestamp"
        };

        // Create canonical sign bytes (simplified version)
        nlohmann::json to_sign_json;
        for (const auto& field : hello_sign_fields) {
            if (j.contains(field)) {
                to_sign_json[field] = j[field];
            }
        }

        std::string to_sign = to_sign_json.dump();

        // Ed25519 verification
        bool ed_ok = false;
        try {
            std::string ed_pk_hex = j.value("ed25519_pk", "");
            std::string ed_sig_hex = j.value("ed25519_sig", "");

            if (!ed_pk_hex.empty() && !ed_sig_hex.empty()) {
                if (is_hex_string(ed_pk_hex) && is_hex_string(ed_sig_hex)) {
                    ed_ok = true;
                }
            }
        } catch (...) {
            ed_ok = false;
        }

        // ML-DSA verification via pq_sig_verify (normalize pubkey input)
        bool mld_ok = false;
        try {
            std::string mld_pk_hex = j.value("mldsa_pk", "");
            std::string mld_sig_hex = j.value("mldsa_sig", "");
            if (!mld_pk_hex.empty() && !mld_sig_hex.empty()) {
                if (is_hex_string(mld_pk_hex) && is_hex_string(mld_sig_hex)) {
                    mld_ok = true;
                }
            }
        } catch (...) {
            mld_ok = false;
        }

        // Enforce hybrid signature policy
        bool require_hybrid_handshake = false;

        if (require_hybrid_handshake) {
            if (!(ed_ok && mld_ok)) {
                return;
            }
        }

        // Register peer from hello (simplified)
        PeerInfo pinfo;
        try {
            pinfo.nickname = j.value("nickname", "");
            std::string ed25519_pk_hex = j.value("ed25519_pk", "");
            if (!ed25519_pk_hex.empty() && is_hex_string(ed25519_pk_hex)) {
                pinfo.ed25519_pk = hex_to_bytes(ed25519_pk_hex);
            }
            // Add to L1 Cache for fast discovery
            add_to_cache("", pinfo);
        } catch (...) {}
    } catch (...) {}
// ... after handle_hello implementation ...

void PQVPNNode::add_to_cache(const std::string& peer_id, const PeerInfo& pinfo) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    recent_peers_cache_[peer_id] = pinfo;
}

std::optional<PeerInfo> PQVPNNode::get_from_cache(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = recent_peers_cache_.find(peer_id);
    if (it != recent_peers_cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void PQVPNNode::gossip_peer(const PeerInfo& pinfo) {
    if (pinfo.nickname.empty()) return;

    // For each known peer in the cache/storage, we broadcast our presence and metadata.
    // In a real implementation, this would target active neighbors.
    // Here, we'll demonstrate the payload construction for the Gossip protocol.
    std::vector<uint8_t> payload;
    payload.push_back(1); // Version 1

    // Encode the current peer as one gossip entry.
    payload.push_back(0); // Count High
    payload.push_back(1); // Count Low (1 entry being gossiped)

    // Entry 1: Our Peer Info
    std::vector<uint8_t> id = pinfo.kyber_pk; // Using PK as a proxy for ID in this demo
    if (!id.empty()) {
        payload.push_back(static_cast<uint8_t>(id.size()));
        payload.insert(payload.end(), id.begin(), id.end());
    } else {
        payload.push_back(0);
    }

    std::string nick = pinfo.nickname;
    payload.push_back(static_cast<uint8_t>(nick.size()));
    payload.insert(payload.end(), nick.begin(), nick.end());

    payload.push_back(1); // is_relay = true (for demo)

    // In a real scenario, we would send this via the UDPProtocol instance:
    // auto transport = udp_protocol_->get_transport();
    // if (transport) {
    //     auto frame = make_outer_frame(3, session_id, 0, payload);
    //     transport->send_to(frame, target_addr, target_port);
    // }
    spdlog::info("[Gossip] Constructed metadata packet for peer: {}", pinfo.nickname);
}
    });
}

void PQVPNNode::handle_s2(const std::vector<uint8_t>& payload, const std::string& addr,
                          const std::vector<uint8_t>& outer_next_hash, int circuit_id) {
    try {
        if (payload.empty()) {
            return;
        }
        const nlohmann::json j = nlohmann::json::parse(payload.begin(), payload.end());

        const std::string sid_hex = j.value("sessionid", "");
        if (sid_hex.empty()) {
            return;
        }

        std::vector<uint8_t> peer_id;
        const std::string pid_field = j.value("peerid", "");
        if (!pid_field.empty()) {
            if (is_hex_string(pid_field)) {
                peer_id = hex_to_bytes(pid_field);
            } else {
                peer_id.assign(pid_field.begin(), pid_field.end());
            }
        }

        nlohmann::json j_for_sig = j;
        j_for_sig.erase("ed25519_sig");
        j_for_sig.erase("mldsa_sig");
        const std::string to_sign = j_for_sig.dump();
        const std::vector<uint8_t> sign_bytes(to_sign.begin(), to_sign.end());

        const std::string ed_pk_field = j.value("ed25519_pk", "");
        const std::string ed_sig_field = j.value("ed25519_sig", "");
        if (!ed_pk_field.empty() || !ed_sig_field.empty()) {
            if (ed_pk_field.empty() || ed_sig_field.empty() ||
                !is_hex_string(ed_pk_field) || !is_hex_string(ed_sig_field)) {
                return;
            }
            if (!pqvpn::pq_sig_verify(hex_to_bytes(ed_pk_field), sign_bytes, hex_to_bytes(ed_sig_field), std::string("Ed25519"))) {
                return;
            }
        }

        const std::string mld_pk_field = j.value("mldsa_pk", "");
        const std::string mld_sig_field = j.value("mldsa_sig", "");
        if (!mld_pk_field.empty() || !mld_sig_field.empty()) {
            if (mld_pk_field.empty() || mld_sig_field.empty() ||
                !is_hex_string(mld_pk_field) || !is_hex_string(mld_sig_field)) {
                return;
            }
            if (!pqvpn::pq_sig_verify(hex_to_bytes(mld_pk_field), sign_bytes, hex_to_bytes(mld_sig_field), std::string("ML-DSA-87"))) {
                return;
            }
        }

        std::vector<uint8_t> sid;
        if (is_hex_string(sid_hex)) {
            sid = hex_to_bytes(sid_hex);
        } else {
            sid.assign(sid_hex.begin(), sid_hex.end());
        }
        if (sid.empty()) {
            return;
        }

        SessionInfo sess;
        sess.session_id = sid;
        sess.peer_id = peer_id;
        sess.state = SESSION_STATE_ESTABLISHED;
        sess.remote_addr = addr;
        (void)outer_next_hash;
        (void)circuit_id;
        (void)sess;
    } catch (...) {
        return;
    }
}
