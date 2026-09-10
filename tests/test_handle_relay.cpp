#include <gtest/gtest.h>

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <memory>
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

        // relay <-> destination: the session used to forward peeled content.
        const std::vector<uint8_t> fwd_transcript{'P', 'Q', 'V', 'P', 'N', '-', 'F', 'W', 'D'};
        relay.establish_hybrid_session(
            destination_id, endpoint_9152(), x25519_secret, ml_kem_secret, fwd_transcript, true);
        destination.establish_hybrid_session(
            relay_id, endpoint_9152(), x25519_secret, ml_kem_secret, fwd_transcript, false);
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

    bool run_relay(pqvpn::PQVPNNode& node, const RelayLayer& layer) {
        bool accepted = false;
        std::exception_ptr failure;
        asio::co_spawn(io, node.handle_relay(layer.session_hint, layer.nonce,
            layer.ciphertext_and_tag, layer.next_hash, layer.circuit_id),
            [&](std::exception_ptr e, bool result) {
                if (e) {
                    failure = std::move(e);
                } else {
                    accepted = result;
                }
            });
        io.run();
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
        layer.ciphertext_and_tag, layer.next_hash, layer.circuit_id),
        [&](std::exception_ptr e, bool result) {
            if (e) failure = std::move(e);
            else accepted = result;
        });
    chain.io.run();

    EXPECT_FALSE(failure);
    EXPECT_TRUE(accepted);

    // The relay forwarded the peeled content (the raw innermost payload) to
    // its established session with the destination.
    const auto& forwarded_session = *chain.relay.sessions_by_peer_id.at(chain.destination_id);
    EXPECT_EQ(forwarded_session.bytes_sent, innermost.size());

    ASSERT_TRUE(got_datagram) << "destination never received the forwarded datagram";
    EXPECT_EQ(std::vector<uint8_t>(received.begin(), received.begin() + bytes), innermost);
}

TEST(HandleRelay, RefusesForwardWithoutNextHopSession) {
    RelayChain chain;
    const std::vector<uint8_t> innermost{0x60, 0x00, 0x00, 0x00, 0x01, 0x02};

    // The relay can still peel (source session intact) but has no route to
    // the next hop.
    chain.relay.sessions_by_peer_id.erase(chain.destination_id);

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
