#include <catch2/catch_test_macros.hpp>

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <exception>
#include <vector>

#include "node_module.hpp"

namespace {

struct ForwardPair {
    asio::io_context io;
    pqvpn::PQVPNNode initiator{io};
    pqvpn::PQVPNNode responder{io};
    std::vector<uint8_t> initiator_id = std::vector<uint8_t>(32, 0x11);
    std::vector<uint8_t> responder_id = std::vector<uint8_t>(32, 0x22);
    asio::ip::udp::endpoint initiator_endpoint{asio::ip::make_address("127.0.0.1"), 9171};
    asio::ip::udp::endpoint responder_endpoint{asio::ip::make_address("127.0.0.1"), 9172};

    ForwardPair() {
        const std::vector<uint8_t> x_secret(32, 0x33);
        const std::vector<uint8_t> y_secret(32, 0x44);
        const std::vector<uint8_t> transcript{'P', 'Q', 'V', 'N', '-', 'F', 'W', 'D'};
        initiator.establish_hybrid_session(
            responder_id, responder_endpoint, x_secret, y_secret, transcript, true);
        responder.establish_hybrid_session(
            initiator_id, initiator_endpoint, x_secret, y_secret, transcript, false);
    }

    bool forward(pqvpn::PQVPNNode& node, std::vector<uint8_t> packet) {
        bool result = false;
        std::exception_ptr failure;
        asio::co_spawn(io, node.forward_adapter_packet(std::move(packet)),
            [&](std::exception_ptr e, bool ok) {
                if (e) {
                    failure = std::move(e);
                } else {
                    result = ok;
                }
            });
        io.run();
        REQUIRE_FALSE(failure);
        return result;
    }
};

} // namespace

TEST_CASE("adapter forwarding selects the established tunnel peer", "[tunnel][forward]") {
    ForwardPair pair;
    REQUIRE(pair.initiator.select_tunnel_peer() == pair.responder_id);
    REQUIRE(pair.responder.select_tunnel_peer() == pair.initiator_id);
}

TEST_CASE("peer selection prefers recent activity with a stable tie-break", "[tunnel][forward]") {
    asio::io_context io;
    pqvpn::PQVPNNode node{io};
    const std::vector<uint8_t> idle(32, 0x10);
    const std::vector<uint8_t> active(32, 0x20);
    const std::vector<uint8_t> x_secret(32, 0x33);
    const std::vector<uint8_t> y_secret(32, 0x44);
    const std::vector<uint8_t> transcript{'S', 'E', 'L'};

    node.establish_hybrid_session(idle, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9173),
        x_secret, y_secret, transcript, true);
    node.establish_hybrid_session(active, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9174),
        x_secret, y_secret, transcript, false);

    auto& idle_session = *node.sessions_by_peer_id.at(idle);
    auto& active_session = *node.sessions_by_peer_id.at(active);

    // The more recently active session carries the packet.
    idle_session.last_activity -= 100.0;
    REQUIRE(node.select_tunnel_peer() == active);

    // Equal activity: deterministic tie-break on peer id (smaller wins).
    active_session.last_activity = idle_session.last_activity;
    REQUIRE(node.select_tunnel_peer() == idle);
}

TEST_CASE("peer selection ignores sessions that are not established", "[tunnel][forward]") {
    asio::io_context io;
    pqvpn::PQVPNNode node{io};
    const std::vector<uint8_t> closing(32, 0x10);
    const std::vector<uint8_t> ready(32, 0x20);
    const std::vector<uint8_t> x_secret(32, 0x33);
    const std::vector<uint8_t> y_secret(32, 0x44);
    const std::vector<uint8_t> transcript{'S', 'T', 'A'};

    node.establish_hybrid_session(closing, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9175),
        x_secret, y_secret, transcript, true);
    node.establish_hybrid_session(ready, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9176),
        x_secret, y_secret, transcript, false);

    // A non-established session is excluded even when it is the most
    // recently active one.
    auto& closing_session = *node.sessions_by_peer_id.at(closing);
    closing_session.last_activity += 100.0;
    closing_session.state = pqvpn::PQVPNNode::SessionState::CLOSING;
    REQUIRE(node.select_tunnel_peer() == ready);

    node.sessions_by_peer_id.erase(ready);
    REQUIRE_FALSE(node.select_tunnel_peer().has_value());
}

TEST_CASE("adapter packet crosses the wire and reaches the peer tunnel sink", "[tunnel][forward]") {
    ForwardPair pair;
    asio::ip::udp::socket initiator_socket(pair.io, pair.initiator_endpoint);
    pair.initiator.transport = &initiator_socket;

    std::vector<uint8_t> captured;
    pair.responder.set_tunnel_packet_handler([&captured](std::vector<uint8_t> p) {
        captured = std::move(p);
    });

    asio::ip::udp::socket responder_socket(pair.io, pair.responder_endpoint);
    const std::vector<uint8_t> packet{0x45, 0x00, 0x00, 0x14, 0xde, 0xad};

    // Register the receive before starting the forward: on MinGW/Asio one
    // io.run() must cover both the posted send and its delivery.
    bool got_datagram = false;
    asio::steady_timer deadline(pair.io, std::chrono::seconds(2));
    deadline.async_wait([&](const asio::error_code&) {
        responder_socket.cancel();
    });

    std::vector<uint8_t> wire(65536);
    asio::ip::udp::endpoint from;
    responder_socket.async_receive_from(asio::buffer(wire), from,
        [&](const asio::error_code& ec, std::size_t n) {
            if (ec) return;
            got_datagram = true;
            auto datagram = std::vector<uint8_t>(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(n));
            asio::co_spawn(pair.io, pair.responder.datagram_received(std::move(datagram), from),
                asio::detached);
        });

    REQUIRE(pair.forward(pair.initiator, packet));
    REQUIRE(got_datagram);
    REQUIRE(captured == packet);
}

TEST_CASE("adapter forwarding fails closed without a session or transport", "[tunnel][forward]") {
    ForwardPair pair;
    // No transport attached: the forward must refuse.
    REQUIRE_FALSE(pair.forward(pair.initiator, std::vector<uint8_t>{0x45, 0x00}));

    asio::ip::udp::socket socket(pair.io, asio::ip::udp::endpoint(asio::ip::make_address("0.0.0.0"), 0));
    pair.initiator.transport = &socket;
    // Transport present but no established session: still refused.
    pqvpn::PQVPNNode bare{pair.io};
    REQUIRE_FALSE(pair.forward(bare, std::vector<uint8_t>{0x45, 0x00}));

    // Empty packet is refused even with a healthy session.
    pair.initiator.sessions_by_peer_id.clear();
    pair.initiator.establish_hybrid_session(
        pair.responder_id, pair.responder_endpoint,
        std::vector<uint8_t>(32, 0x33), std::vector<uint8_t>(32, 0x44),
        std::vector<uint8_t>{'E', 'M', 'P'}, true);
    REQUIRE_FALSE(pair.forward(pair.initiator, {}));
}
