#include <gtest/gtest.h>

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "node_module.hpp"

namespace {

struct RelayChain {
    asio::io_context io;
    pqvpn::PQVPNNode source{io};
    pqvpn::PQVPNNode relay{io};
    pqvpn::PQVPNNode destination{io};

    std::vector<uint8_t> source_id = std::vector<uint8_t>(32, 0xAA);
    std::vector<uint8_t> relay_id = std::vector<uint8_t>(32, 0xBB);
    std::vector<uint8_t> destination_id = std::vector<uint8_t>(32, 0xCC);

    RelayChain() {
        source.set_my_id(source_id);
        relay.set_my_id(relay_id);
        destination.set_my_id(destination_id);

        const std::vector<uint8_t> x25519_secret(32, 0x33);
        const std::vector<uint8_t> ml_kem_secret(32, 0x44);
        const std::vector<uint8_t> transcript{'P', 'Q', 'V', 'P', 'N', '-', 'R', 'L', 'Y'};

        // source <-> relay: the session that encrypts/peels the outer layer.
        relay.establish_hybrid_session(
            source_id, endpoint_9151(), x25519_secret, ml_kem_secret, transcript, true);
        source.establish_hybrid_session(
            relay_id, endpoint_9151(), x25519_secret, ml_kem_secret, transcript, false);

        // The destination is known to the relay through discovery (mesh) but
        // carries no session: forwarding only needs its network address. This
        // is exactly the topology main.py's handle_relay resolves — it looks
        // up the next hop in mesh.peers, not in its own sessions.
        pqvpn::PQVPNNode::PeerInfo dest_info;
        dest_info.peer_id = destination_id;
        dest_info.address = endpoint_9152();
        relay.mesh.peers[hex_id(destination_id)] = dest_info;
    }

    static std::string hex_id(const std::vector<uint8_t>& id) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto b : id) ss << std::setw(2) << static_cast<int>(b);
        return ss.str();
    }

    static asio::ip::udp::endpoint endpoint_9151() {
        return asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9151);
    }

    static asio::ip::udp::endpoint endpoint_9152() {
        return asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9152);
    }

    // One outer RELAY frame split into its dispatchable parts (main.py
    // _process_outer_datagram FT_RELAY branch).
    struct RelayLayer {
        std::vector<uint8_t> next_hash;
        uint32_t circuit_id = 0;
        std::vector<uint8_t> session_hint;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> ciphertext_and_tag;
    };

    static RelayLayer split_outer_frame(const std::vector<uint8_t>& frame) {
        EXPECT_GE(frame.size(), 16u + 8u + 12u + 16u);
        RelayLayer layer;
        if (frame.size() < 36) return layer;
        layer.next_hash.assign(frame.begin() + 2, frame.begin() + 10);
        layer.circuit_id =
            (static_cast<uint32_t>(frame[10]) << 24) |
            (static_cast<uint32_t>(frame[11]) << 16) |
            (static_cast<uint32_t>(frame[12]) << 8) |
            static_cast<uint32_t>(frame[13]);
        const auto payload_begin = frame.begin() + 16;
        layer.session_hint.assign(payload_begin, payload_begin + 8);
        layer.nonce.assign(payload_begin + 8, payload_begin + 20);
        layer.ciphertext_and_tag.assign(payload_begin + 20, frame.end());
        return layer;
    }

    // `sender` defaults to the source's registered endpoint: the first peeler
    // always receives directly from the onion source.
    bool run_relay(pqvpn::PQVPNNode& node, const RelayLayer& layer,
                   const asio::ip::udp::endpoint& sender = endpoint_9151()) {
        bool accepted = false;
        std::exception_ptr failure;
        asio::co_spawn(io, node.handle_relay(layer.session_hint, layer.nonce,
            layer.ciphertext_and_tag, layer.next_hash, layer.circuit_id, sender),
            [&](std::exception_ptr e, bool result) {
                if (e) {
                    failure = std::move(e);
                } else {
                    accepted = result;
                }
            });
        io.run();
        // Restart the context: asio stops it once the work queue drains, and a
        // later co_spawn + run() on a stopped context would never execute.
        io.restart();
        EXPECT_FALSE(failure);
        return accepted;
    }

    // Builds a two-hop onion source -> relay -> destination and returns the
    // outer frame.
    std::optional<std::vector<uint8_t>> build_onion(const std::vector<uint8_t>& innermost) {
        return source.build_onion_frame_with_circuit(
            {relay_id, destination_id}, innermost, 0);
    }
};

// Three-node chain for the multi-peel boundary: source builds an onion whose
// outer layer is peeled by `first`, which then forwards the inner (raw) layer
// to `second`. This mirrors main.py's [A,B,C] relay scenario.
struct MultiPeelChain {
    asio::io_context io;
    pqvpn::PQVPNNode source{io};
    pqvpn::PQVPNNode first{io};   // peels the outer layer, then forwards
    pqvpn::PQVPNNode second{io};  // would-be second peeler

    std::vector<uint8_t> source_id = std::vector<uint8_t>(32, 0xA1);
    std::vector<uint8_t> first_id  = std::vector<uint8_t>(32, 0xB1);
    std::vector<uint8_t> second_id = std::vector<uint8_t>(32, 0xC1);

    MultiPeelChain() {
        source.set_my_id(source_id);
        first.set_my_id(first_id);
        second.set_my_id(second_id);

        const std::vector<uint8_t> ml_kem_secret(32, 0x72);
        const std::vector<uint8_t> transcript{'M', 'P', 'C'};

        // source <-> first: the session that encrypts/peels the outer layer.
        const std::vector<uint8_t> x_first(32, 0x71);
        first.establish_hybrid_session(source_id, endpoint_first(), x_first, ml_kem_secret, transcript, true);
        source.establish_hybrid_session(first_id, endpoint_first(), x_first, ml_kem_secret, transcript, false);

        // source <-> second: the session that encrypts the inner layer (the one
        // first would forward). A distinct secret yields a distinct session id,
        // so neither side sees an ambiguous hint.
        const std::vector<uint8_t> x_second(32, 0x73);
        second.establish_hybrid_session(source_id, endpoint_second(), x_second, ml_kem_secret, transcript, true);
        source.establish_hybrid_session(second_id, endpoint_second(), x_second, ml_kem_secret, transcript, false);

        // first learns second's address through discovery (mesh) so it can
        // forward to it — the topology main.py's handle_relay resolves via mesh.peers.
        pqvpn::PQVPNNode::PeerInfo s_info;
        s_info.peer_id = second_id;
        s_info.address = endpoint_second();
        first.mesh.peers[hex_id(second_id)] = s_info;
    }

    static std::string hex_id(const std::vector<uint8_t>& id) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto b : id) ss << std::setw(2) << static_cast<int>(b);
        return ss.str();
    }

    static asio::ip::udp::endpoint endpoint_first() {
        return asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9301);
    }

    static asio::ip::udp::endpoint endpoint_second() {
        return asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9302);
    }

    // One outer RELAY frame split into its dispatchable parts (same shape as
    // RelayChain::split_outer_frame).
    struct RelayLayer {
        std::vector<uint8_t> next_hash;
        uint32_t circuit_id = 0;
        std::vector<uint8_t> session_hint;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> ciphertext_and_tag;
    };

    static RelayLayer split_outer_frame(const std::vector<uint8_t>& frame) {
        EXPECT_GE(frame.size(), 16u + 8u + 12u + 16u);
        RelayLayer layer;
        if (frame.size() < 36) return layer;
        layer.next_hash.assign(frame.begin() + 2, frame.begin() + 10);
        layer.circuit_id =
            (static_cast<uint32_t>(frame[10]) << 24) |
            (static_cast<uint32_t>(frame[11]) << 16) |
            (static_cast<uint32_t>(frame[12]) << 8) |
            static_cast<uint32_t>(frame[13]);
        const auto payload_begin = frame.begin() + 16;
        layer.session_hint.assign(payload_begin, payload_begin + 8);
        layer.nonce.assign(payload_begin + 8, payload_begin + 20);
        layer.ciphertext_and_tag.assign(payload_begin + 20, frame.end());
        return layer;
    }

    // Two-peeler onion: source -> first -> second (path length three). The
    // builder needs a session with each peeling hop (first and second); the
    // final element is only hashed as the innermost next-hop.
    std::optional<std::vector<uint8_t>> build_onion(const std::vector<uint8_t>& innermost) {
        const std::vector<uint8_t> destination(32, 0xD1);
        return source.build_onion_frame_with_circuit(
            {first_id, second_id, destination}, innermost, 0);
    }
};

} // namespace

TEST(HandleRelay, UnknownSessionHintIsRejected) {
    RelayChain chain;
    const auto frame = chain.build_onion({0x45, 0x00});
    ASSERT_TRUE(frame.has_value());
    auto layer = chain.split_outer_frame(*frame);
    layer.session_hint.assign(8, 0xFF);

    EXPECT_FALSE(chain.run_relay(chain.relay, layer));
}

TEST(HandleRelay, MisroutedLayerIsRejected) {
    RelayChain chain;
    const auto frame = chain.build_onion({0x45, 0x00});
    ASSERT_TRUE(frame.has_value());
    auto layer = chain.split_outer_frame(*frame);

    // The header must identify the peeling node (relay), not the final hop.
    layer.next_hash = chain.source.peer_hash8(chain.destination_id);
    EXPECT_FALSE(chain.run_relay(chain.relay, layer));
}

TEST(HandleRelay, InvalidTagIsRejected) {
    RelayChain chain;
    const auto frame = chain.build_onion({0x45, 0x00});
    ASSERT_TRUE(frame.has_value());
    auto layer = chain.split_outer_frame(*frame);
    ASSERT_GE(layer.ciphertext_and_tag.size(), 16u);
    layer.ciphertext_and_tag[0] ^= 0x80; // Corrupt the ciphertext.

    EXPECT_FALSE(chain.run_relay(chain.relay, layer));
}

TEST(HandleRelay, ReplayedNonceIsRejected) {
    RelayChain chain;
    // A transport is required for the (successful) first forward.
    asio::ip::udp::socket relay_socket(chain.io,
        asio::ip::udp::endpoint(asio::ip::make_address("0.0.0.0"), 0));
    chain.relay.transport = &relay_socket;

    const auto frame = chain.build_onion({0x45, 0x00});
    ASSERT_TRUE(frame.has_value());
    const auto layer = chain.split_outer_frame(*frame);

    EXPECT_TRUE(chain.run_relay(chain.relay, layer));
    // Same session hint + nonce again: replay window must reject it.
    EXPECT_FALSE(chain.run_relay(chain.relay, layer));
}

TEST(HandleRelay, RelaysPeeledLayerToTheNextHop) {
    RelayChain chain;
    const std::vector<uint8_t> innermost{0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04};

    // Real loopback sockets: the relay sends through its transport and the
    // destination receives the forwarded datagram.
    asio::ip::udp::socket relay_socket(chain.io,
        asio::ip::udp::endpoint(asio::ip::make_address("0.0.0.0"), 0));
    chain.relay.transport = &relay_socket;
    asio::ip::udp::socket destination_socket(chain.io, chain.endpoint_9152());

    const auto frame = chain.build_onion(innermost);
    ASSERT_TRUE(frame.has_value());
    const auto layer = chain.split_outer_frame(*frame);

    // Register the receive BEFORE starting the relay: on MinGW/Asio a second
    // io.run() after coroutines have executed does not process queued work, so
    // one run must cover both the forward and its delivery.
    std::vector<uint8_t> received(65536);
    asio::ip::udp::endpoint from;
    bool got_datagram = false;
    bool accepted = false;
    std::exception_ptr failure;
    std::size_t bytes = 0;
    asio::steady_timer deadline(chain.io, std::chrono::seconds(2));
    deadline.async_wait([&](const asio::error_code&) {
        destination_socket.cancel();
    });
    destination_socket.async_receive_from(asio::buffer(received), from,
        [&](const asio::error_code& ec, std::size_t n) {
            if (!ec) {
                got_datagram = true;
                bytes = n;
            }
            deadline.cancel();
        });

    asio::co_spawn(chain.io, chain.relay.handle_relay(layer.session_hint, layer.nonce,
        layer.ciphertext_and_tag, layer.next_hash, layer.circuit_id,
        chain.endpoint_9151()),
        [&](std::exception_ptr e, bool result) {
            if (e) failure = std::move(e);
            else accepted = result;
        });
    chain.io.run();

    EXPECT_FALSE(failure);
    EXPECT_TRUE(accepted);

    // The relay forwarded the peeled content to the destination's mesh address
    // even though it holds no session with it.
    EXPECT_EQ(chain.relay.sessions_by_peer_id.count(chain.destination_id), 0u);

    ASSERT_TRUE(got_datagram) << "destination never received the forwarded datagram";
    const std::vector<uint8_t> got(received.begin(), received.begin() + bytes);
    // The forward is wrapped in a RELAY_FRAME (version/type/next-hop/circuit/
    // length header) so any dispatcher can route it; main.py's raw forward
    // would be undeliverable at the next hop. Recorded in MIGRATION_MANIFEST.md.
    const auto expected = chain.source.make_outer_frame(
        pqvpn::PQVPNNode::RELAY_FRAME, chain.relay.peer_hash8(chain.destination_id), 0, innermost);
    EXPECT_EQ(got, expected);
}

TEST(HandleRelay, RelayLayerFromForeignEndpointIsRejected) {
    RelayChain chain;
    // A transport is required for the (successful) forward on acceptance.
    asio::ip::udp::socket relay_socket(chain.io,
        asio::ip::udp::endpoint(asio::ip::make_address("0.0.0.0"), 0));
    chain.relay.transport = &relay_socket;

    const auto frame = chain.build_onion({0x45, 0x00});
    ASSERT_TRUE(frame.has_value());
    const auto layer = chain.split_outer_frame(*frame);

    // The same valid layer is rejected when it arrives from an address the
    // session was not established with (sender binding), and accepted again
    // from the registered source endpoint.
    EXPECT_FALSE(chain.run_relay(
        chain.relay, layer,
        asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9999)));
    EXPECT_TRUE(chain.run_relay(chain.relay, layer));
}

TEST(HandleRelay, RefusesForwardWhenNextHopIsUnknown) {
    RelayChain chain;
    const std::vector<uint8_t> innermost{0x60, 0x00, 0x00, 0x00, 0x01, 0x02};

    // The relay can still peel (source session intact) but has no route to
    // the next hop: it is absent from both its mesh and its sessions.
    chain.relay.mesh.peers.clear();

    const auto frame = chain.build_onion(innermost);
    ASSERT_TRUE(frame.has_value());
    const auto layer = chain.split_outer_frame(*frame);

    EXPECT_FALSE(chain.run_relay(chain.relay, layer));
}

TEST(HandleRelay, LocalDeliveryDeliversDecryptedPacket) {
    RelayChain chain;
    // The inner data frame and the onion layer must ride on separate sessions:
    // sharing one session would put both nonces in the relay's per-session
    // replay window and the older counter would be rejected as a replay.
    pqvpn::PQVPNNode bob{chain.io};
    const std::vector<uint8_t> bob_id(32, 0xE2);
    bob.set_my_id(bob_id);

    const std::vector<uint8_t> x_secret(32, 0x55);
    const std::vector<uint8_t> y_secret(32, 0x66);
    const std::vector<uint8_t> bob_transcript{'B', 'O', 'B'};
    chain.relay.establish_hybrid_session(
        bob_id, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9154),
        x_secret, y_secret, bob_transcript, true);
    bob.establish_hybrid_session(
        chain.relay_id, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9154),
        x_secret, y_secret, bob_transcript, false);

    const std::vector<uint8_t> packet{0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04};

    // Bob's application frame is a tunnel data datagram for the relay itself.
    const auto data_frame = bob.build_tunnel_datagram(
        chain.relay_id, std::span<const uint8_t>(packet));
    ASSERT_TRUE(data_frame.has_value());

    // source wraps it in an onion whose final destination is the relay.
    const auto onion = chain.source.build_onion_frame_with_circuit(
        {chain.relay_id, chain.relay_id}, *data_frame, 0);
    ASSERT_TRUE(onion.has_value());
    const auto layer = chain.split_outer_frame(*onion);

    std::vector<uint8_t> captured;
    chain.relay.set_tunnel_packet_handler([&captured](std::vector<uint8_t> p) {
        captured = std::move(p);
    });

    EXPECT_TRUE(chain.run_relay(chain.relay, layer));
    EXPECT_EQ(captured, packet);
}

TEST(HandleRelay, LocalDeliveryFailsClosedWithoutAPacketSink) {
    RelayChain chain;
    const std::vector<uint8_t> packet{0x45, 0x00, 0x01};

    const auto data_frame = chain.source.build_tunnel_datagram(
        chain.relay_id, std::span<const uint8_t>(packet));
    ASSERT_TRUE(data_frame.has_value());
    const auto onion = chain.source.build_onion_frame_with_circuit(
        {chain.relay_id, chain.relay_id}, *data_frame, 0);
    ASSERT_TRUE(onion.has_value());
    const auto layer = chain.split_outer_frame(*onion);

    // No tunnel_packet_handler_ registered: the relay must not deliver.
    bool delivered = false;
    EXPECT_FALSE(chain.run_relay(chain.relay, layer));
    EXPECT_FALSE(delivered);
}

TEST(HandleRelay, LocalDeliveryIsolatesAThrowingSink) {
    RelayChain chain;
    pqvpn::PQVPNNode bob{chain.io};
    const std::vector<uint8_t> bob_id(32, 0xE2);
    bob.set_my_id(bob_id);

    const std::vector<uint8_t> x_secret(32, 0x55);
    const std::vector<uint8_t> y_secret(32, 0x66);
    const std::vector<uint8_t> bob_transcript{'B', 'O', 'B'};
    chain.relay.establish_hybrid_session(
        bob_id, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9154),
        x_secret, y_secret, bob_transcript, true);
    bob.establish_hybrid_session(
        chain.relay_id, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9154),
        x_secret, y_secret, bob_transcript, false);

    const std::vector<uint8_t> packet{0x45, 0x00, 0x00, 0x14, 0x01};
    const auto data_frame = bob.build_tunnel_datagram(
        chain.relay_id, std::span<const uint8_t>(packet));
    ASSERT_TRUE(data_frame.has_value());

    const auto onion = chain.source.build_onion_frame_with_circuit(
        {chain.relay_id, chain.relay_id}, *data_frame, 0);
    ASSERT_TRUE(onion.has_value());
    const auto layer = chain.split_outer_frame(*onion);

    int sink_calls = 0;
    chain.relay.set_tunnel_packet_handler([&sink_calls](std::vector<uint8_t>) {
        ++sink_calls;
        throw std::runtime_error("adapter is closed");
    });

    // The relay completes without an escaped exception even though the sink
    // throws: delivery was attempted, the frame dropped, and the node stays up.
    EXPECT_TRUE(chain.run_relay(chain.relay, layer));
    EXPECT_EQ(sink_calls, 1);
}

TEST(HandleRelay, LocalDeliveryRejectsShortDeclaredBody) {
    RelayChain chain;
    // Inner frame with a valid 16-byte header that declares only a 4-byte body,
    // followed by trailing bytes so the whole frame looks large enough to hold
    // nonce(12) + tag(16). The declared body length must bound every slice.
    std::vector<uint8_t> inner(16, 0);
    inner[0] = 1;                                    // version
    inner[1] = pqvpn::PQVPNNode::TUNNEL_DATA_FRAME;  // type
    const auto hint = chain.relay.sessions_by_peer_id.at(chain.source_id)->session_id;
    std::copy(hint.begin(), hint.begin() + 8, inner.begin() + 2);
    inner[15] = 4;                                   // declared body length
    inner.insert(inner.end(), 32, 0xAB);             // trailing bytes

    const auto onion = chain.source.build_onion_frame_with_circuit(
        {chain.relay_id, chain.relay_id}, inner, 0);
    ASSERT_TRUE(onion.has_value());
    const auto layer = chain.split_outer_frame(*onion);

    std::vector<uint8_t> captured;
    chain.relay.set_tunnel_packet_handler([&captured](std::vector<uint8_t> p) {
        captured = std::move(p);
    });

    EXPECT_FALSE(chain.run_relay(chain.relay, layer));
    EXPECT_TRUE(captured.empty());
}

TEST(HandleRelay, LocalDeliveryRejectsDataFramesWithForeignLayout) {
    RelayChain chain;
    // main.py's FT_DATA body carries its own session id first; this codebase
    // has no builder for that shape, so a type-3 inner frame must be rejected
    // by policy even when it is well-formed and long enough.
    std::vector<uint8_t> inner(16 + 28, 0x5A);
    inner[0] = 1;                            // version
    inner[1] = pqvpn::PQVPNNode::DATA_FRAME; // FT_DATA per main.py constants
    const auto hint = chain.relay.sessions_by_peer_id.at(chain.source_id)->session_id;
    std::copy(hint.begin(), hint.begin() + 8, inner.begin() + 2);
    inner[14] = 0;
    inner[15] = 28;                          // declared body length

    const auto onion = chain.source.build_onion_frame_with_circuit(
        {chain.relay_id, chain.relay_id}, inner, 0);
    ASSERT_TRUE(onion.has_value());
    const auto layer = chain.split_outer_frame(*onion);

    std::vector<uint8_t> captured;
    chain.relay.set_tunnel_packet_handler([&captured](std::vector<uint8_t> p) {
        captured = std::move(p);
    });

    EXPECT_FALSE(chain.run_relay(chain.relay, layer));
    EXPECT_TRUE(captured.empty());
}

// End-to-end multi-peel through the REAL dispatchers: source -> first -> second.
// first receives the outer frame via datagram_received (direct origin), peels
// it, and forwards the wrapped layer to second's mesh address; second receives
// that forward through its own datagram_received (relay origin — first is a
// mesh-registered peer at the address it sent from), peels its layer, and
// forwards the final content. Only genuine AEAD success at both hops produces
// the exact wrapped output captured below.
TEST(HandleRelay, MultiPeelDeliversThroughRealDispatchers) {
    MultiPeelChain chain;
    const std::vector<uint8_t> innermost{0x45, 0x00, 0x00, 0x14, 0x01, 0x02};
    const std::vector<uint8_t> destination(32, 0xD1);

    // first forwards from a stable endpoint that second knows through discovery
    // (relay origin for sender binding); the final content lands at a capture
    // socket registered as destination's mesh address.
    static constexpr unsigned kFirstForwardPort = 9303;
    static constexpr unsigned kDestinationPort = 9304;
    const auto first_forward_endpoint =
        asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), kFirstForwardPort);
    const auto destination_endpoint =
        asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), kDestinationPort);

    pqvpn::PQVPNNode::PeerInfo first_info;
    first_info.peer_id = chain.first_id;
    first_info.address = first_forward_endpoint;
    chain.second.mesh.peers[chain.hex_id(chain.first_id)] = first_info;

    pqvpn::PQVPNNode::PeerInfo dest_info;
    dest_info.peer_id = destination;
    dest_info.address = destination_endpoint;
    chain.second.mesh.peers[chain.hex_id(destination)] = dest_info;

    asio::ip::udp::socket first_socket(chain.io, first_forward_endpoint);
    chain.first.transport = &first_socket;
    asio::ip::udp::socket second_socket(chain.io, chain.endpoint_second());
    chain.second.transport = &second_socket;
    asio::ip::udp::socket capture(chain.io, destination_endpoint);

    const auto frame = chain.build_onion(innermost);
    ASSERT_TRUE(frame.has_value());

    // Register every receive before any send: one io.run() must cover the whole
    // two-peel exchange (MinGW/Asio does not process queued work on a later run).
    std::vector<uint8_t> second_wire(65536);
    asio::ip::udp::endpoint second_from;
    second_socket.async_receive_from(asio::buffer(second_wire), second_from,
        [&](const asio::error_code& ec, std::size_t n) {
            if (ec) return;
            auto datagram = std::vector<uint8_t>(second_wire.begin(),
                second_wire.begin() + static_cast<std::ptrdiff_t>(n));
            asio::co_spawn(chain.io, chain.second.datagram_received(std::move(datagram), second_from),
                asio::detached);
        });

    std::vector<uint8_t> forwarded(65536);
    asio::ip::udp::endpoint from;
    bool got_forward = false;
    std::size_t fwd_bytes = 0;
    asio::steady_timer deadline(chain.io, std::chrono::seconds(2));
    deadline.async_wait([&](const asio::error_code&) { capture.cancel(); });
    capture.async_receive_from(asio::buffer(forwarded), from,
        [&](const asio::error_code& ec, std::size_t n) {
            if (!ec) { got_forward = true; fwd_bytes = n; }
            deadline.cancel();
        });

    // The outer frame enters first through its real dispatcher, from the source's
    // registered endpoint (direct origin).
    asio::co_spawn(chain.io,
        chain.first.datagram_received(*frame, chain.endpoint_first()),
        [](std::exception_ptr) {});
    chain.io.run();

    ASSERT_TRUE(got_forward)
        << "second never received the forwarded layer: the second peel did not happen";
    const std::vector<uint8_t> got(forwarded.begin(), forwarded.begin() + fwd_bytes);
    // After BOTH peels, what reaches destination is the final content wrapped in
    // a RELAY_FRAME identifying it — proof that first peeled hop one and second
    // peeled hop two (each peel requires AEAD success under its own session).
    const auto expected = chain.source.make_outer_frame(
        pqvpn::PQVPNNode::RELAY_FRAME, chain.second.peer_hash8(destination), 0, innermost);
    EXPECT_EQ(got, expected);
}

// A forwarded layer arriving from an address that is neither the session's
// registered peer nor a mesh-registered relay must be rejected: sender binding
// still applies to hop two and later, it just accepts the relay origin instead
// of the source endpoint. Acceptance would be observable as second peeling its
// layer and re-forwarding the final content; rejection leaves nothing behind.
TEST(HandleRelay, ForwardedLayerFromUnregisteredSenderIsRejected) {
    MultiPeelChain chain;
    const std::vector<uint8_t> innermost{0x45, 0x00, 0x00, 0x14, 0x01, 0x02};
    const std::vector<uint8_t> destination(32, 0xD1);

    // first forwards from an EPHEMERAL socket that second does not know through
    // discovery: neither direct origin (source endpoint) nor relay origin.
    asio::ip::udp::socket first_socket(chain.io,
        asio::ip::udp::endpoint(asio::ip::make_address("0.0.0.0"), 0));
    chain.first.transport = &first_socket;

    // If second were to (wrongly) accept the layer, it would peel and forward
    // the final content here; that is what we observe.
    static constexpr unsigned kDestinationPort = 9305;
    const auto destination_endpoint =
        asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), kDestinationPort);
    pqvpn::PQVPNNode::PeerInfo dest_info;
    dest_info.peer_id = destination;
    dest_info.address = destination_endpoint;
    chain.second.mesh.peers[chain.hex_id(destination)] = dest_info;

    asio::ip::udp::socket second_socket(chain.io, chain.endpoint_second());
    chain.second.transport = &second_socket;
    asio::ip::udp::socket capture(chain.io, destination_endpoint);

    const auto frame = chain.build_onion(innermost);
    ASSERT_TRUE(frame.has_value());
    const auto layer = chain.split_outer_frame(*frame);

    // second's real dispatcher handles whatever first forwards.
    std::vector<uint8_t> second_wire(65536);
    asio::ip::udp::endpoint second_from;
    bool got_forward = false;
    asio::steady_timer deadline(chain.io, std::chrono::seconds(2));
    deadline.async_wait([&](const asio::error_code&) { capture.cancel(); });
    second_socket.async_receive_from(asio::buffer(second_wire), second_from,
        [&](const asio::error_code& ec, std::size_t n) {
            if (ec) return;
            auto datagram = std::vector<uint8_t>(second_wire.begin(),
                second_wire.begin() + static_cast<std::ptrdiff_t>(n));
            asio::co_spawn(chain.io, chain.second.datagram_received(std::move(datagram), second_from),
                asio::detached);
        });
    std::vector<uint8_t> capture_wire(65536);
    asio::ip::udp::endpoint capture_from;
    capture.async_receive_from(asio::buffer(capture_wire), capture_from,
        [&](const asio::error_code& ec, std::size_t) {
            if (!ec) got_forward = true;
            deadline.cancel();
        });

    bool accepted = false;
    std::exception_ptr failure;
    asio::co_spawn(chain.io, chain.first.handle_relay(
        layer.session_hint, layer.nonce, layer.ciphertext_and_tag,
        layer.next_hash, layer.circuit_id, chain.endpoint_first()),
        [&](std::exception_ptr e, bool result) {
            if (e) failure = std::move(e); else accepted = result;
        });
    chain.io.run();

    EXPECT_FALSE(failure);
    EXPECT_TRUE(accepted) << "the first peeler must accept the layer from its source";
    // second's dispatcher rejected the forwarded layer (unregistered sender),
    // so nothing was peeled and nothing re-forwarded.
    EXPECT_FALSE(got_forward)
        << "a forwarded layer from an unregistered address must be rejected at hop two";
}
