#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "config_module.hpp"
#include "network_module.hpp"
#include "node_identity.hpp"
#include "node_module.hpp"

using namespace pqvpn;
using namespace std::chrono_literals;

namespace {

// One node with its own io_context, UDP listener on loopback, and a freshly
// generated hybrid identity (Ed25519 + X25519 + ML-KEM-1024 + ML-DSA-87).
struct TestNode {
    asio::io_context io;
    std::shared_ptr<PQVPNNode> node;
    std::unique_ptr<network::UdpListener> listener;

    explicit TestNode(uint16_t port) : node(std::make_shared<PQVPNNode>(io)) {
        const auto identity = identity::NodeIdentity::generate();
        node->ed25519_private_key = identity.ed25519_sk;
        node->ed25519_public_key = identity.ed25519_pk;
        node->x25519_private_key = identity.x25519_sk;
        node->x25519_public_key = identity.x25519_pk;
        node->ml_kem_secret_key = identity.ml_kem_sk;
        node->ml_kem_public_key = identity.ml_kem_pk;
        node->ml_dsa_private_key = identity.mldsa_sk;
        node->ml_dsa_public_key = identity.mldsa_pk;
        REQUIRE(node->establish_identity());

        config::NetworkConfig net;
        net.port = port;
        net.bind_address = "127.0.0.1";
        listener = std::make_unique<network::UdpListener>(io, net);
        auto captured = node;
        listener->set_receive_handler(
            [captured](std::vector<uint8_t> packet, const asio::ip::udp::endpoint& sender) {
                asio::co_spawn(captured->get_io_context(),
                    captured->datagram_received(std::move(packet), sender), asio::detached);
            });
        REQUIRE(listener->start().has_value());
        node->transport = &listener->socket();
    }

    bool has_established_session_with(const asio::ip::udp::endpoint& remote) const {
        return std::any_of(
            node->sessions_by_peer_id.begin(), node->sessions_by_peer_id.end(),
            [&](const auto& entry) {
                const auto* session = entry.second.get();
                return (session &&
                        session->state == PQVPNNode::SessionState::ESTABLISHED &&
                        session->remote_addr == remote);
            });
    }

    std::vector<uint8_t> peer_id_at(const asio::ip::udp::endpoint& remote) const {
        for (const auto& [peer_id, session] : node->sessions_by_peer_id) {
            if (session && session->remote_addr == remote) return peer_id;
        }
        return {};
    }
};

// 32 bytes of a single hex digit: stand-in key material for forged frames.
std::string hex32(char c) {
    return std::string(64, c);
}

} // namespace

TEST_CASE("two nodes complete the hybrid handshake and exchange tunnel data", "[handshake][integration]") {
    TestNode a(19091);
    TestNode b(19092);

    const asio::ip::udp::endpoint endpoint_a(asio::ip::make_address("127.0.0.1"), 19091);
    const asio::ip::udp::endpoint endpoint_b(asio::ip::make_address("127.0.0.1"), 19092);

    // Tunnel data sinks: whatever each node decrypts from the peer lands here.
    std::vector<uint8_t> received_at_a;
    std::atomic<bool> got_at_a{false};
    a.node->set_tunnel_packet_handler(
        [&](std::vector<uint8_t> packet, const std::vector<uint8_t>& /*src*/) {
            received_at_a = std::move(packet);
            got_at_a = true;
        });
    std::vector<uint8_t> received_at_b;
    std::atomic<bool> got_at_b{false};
    b.node->set_tunnel_packet_handler(
        [&](std::vector<uint8_t> packet, const std::vector<uint8_t>& /*src*/) {
            received_at_b = std::move(packet);
            got_at_b = true;
        });

    // Same wiring as main.cpp: each node bootstraps toward the other. The
    // deterministic initiator (smaller identity) drives S1/S2 exactly once.
    asio::co_spawn(a.io, a.node->bootstrap_peers({endpoint_b}), asio::detached);
    asio::co_spawn(b.io, b.node->bootstrap_peers({endpoint_a}), asio::detached);

    std::thread runner_a([&] { a.io.run(); });
    std::thread runner_b([&] { b.io.run(); });

    const auto fail = [&] {
        a.io.stop();
        b.io.stop();
        if (runner_a.joinable()) runner_a.join();
        if (runner_b.joinable()) runner_b.join();
    };

    // Wait for both sides to report an established session (ML-KEM-1024 +
    // ML-DSA-87 signing makes this a few tens of ms, allow generous headroom).
    const auto deadline = std::chrono::steady_clock::now() + 30s;
    while (std::chrono::steady_clock::now() < deadline) {
        if (a.has_established_session_with(endpoint_b) &&
            b.has_established_session_with(endpoint_a)) {
            break;
        }
        std::this_thread::sleep_for(100ms);
    }

    REQUIRE(a.has_established_session_with(endpoint_b));
    REQUIRE(b.has_established_session_with(endpoint_a));

    // Data plane, A -> B: the packet must decrypt at B with identical bytes.
    const std::string message_ab = "pqvpn-handshake-proof-a-to-b";
    const auto b_id_at_a = a.peer_id_at(endpoint_b);
    REQUIRE_FALSE(b_id_at_a.empty());
    REQUIRE(a.node->send_tunnel_packet(b_id_at_a,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(message_ab.data()),
                                 message_ab.size())));

    const auto data_deadline = std::chrono::steady_clock::now() + 10s;
    while (!got_at_b && std::chrono::steady_clock::now() < data_deadline) {
        std::this_thread::sleep_for(50ms);
    }
    REQUIRE(got_at_b);
    REQUIRE(std::string(received_at_b.begin(), received_at_b.end()) == message_ab);

    // Data plane, B -> A: symmetric direction through the same session keys.
    const std::string message_ba = "pqvpn-handshake-proof-b-to-a";
    const auto a_id_at_b = b.peer_id_at(endpoint_a);
    REQUIRE_FALSE(a_id_at_b.empty());
    REQUIRE(b.node->send_tunnel_packet(a_id_at_b,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(message_ba.data()),
                                 message_ba.size())));

    while (!got_at_a && std::chrono::steady_clock::now() < data_deadline) {
        std::this_thread::sleep_for(50ms);
    }
    REQUIRE(got_at_a);
    REQUIRE(std::string(received_at_a.begin(), received_at_a.end()) == message_ba);

    fail(); // stop both io_contexts and join the runners
}

TEST_CASE("handshake rejects a HELLO with an invalid hybrid signature", "[handshake][security]") {
    TestNode a(19093);
    std::thread runner_a([&] { a.io.run(); });

    // Forge a HELLO: valid shape, but the Ed25519 signature is garbage. The
    // node must not register the peer and must not reply or initiate.
    nlohmann::json hello = {
        {"peerid", hex32('a')},
        {"nickname", "forger"},
        {"ed25519_pk", hex32('e')},
        {"x25519_pk", hex32('x')},
        {"ml_kem_pk", hex32('k')},
        {"mldsa_pk", hex32('d')},
        {"timestamp", 1234567890},
        {"response", false},
        {"sessionid", std::string{}}
    };
    hello["ed25519_sig"] = hex32('s');
    hello["mldsa_sig"] = hex32('t');

    const auto wire = hello.dump();
    auto frame = a.node->make_outer_frame(
        PQVPNNode::HELLO_FRAME, std::vector<uint8_t>(8, 0), 0,
        std::vector<uint8_t>(wire.begin(), wire.end()));
    // Deliver it to the node's own listener so datagram_received sees it.
    asio::ip::udp::endpoint forger(asio::ip::make_address("127.0.0.1"), 19093);
    a.node->transport->send_to(asio::buffer(frame), forger, 0);

    // Let the (rejected) frame be processed.
    std::this_thread::sleep_for(500ms);
    REQUIRE(a.node->sessions_by_peer_id.empty());
    REQUIRE(a.node->mesh.peers.empty());

    a.io.stop();
    if (runner_a.joinable()) runner_a.join();
}
