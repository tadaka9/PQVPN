#include <catch2/catch_test_macros.hpp>

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <stdexcept>
#include <vector>

#include "node_module.hpp"

namespace {

struct SinkHarness {
    asio::io_context io;
    pqvpn::PQVPNNode initiator{io};
    pqvpn::PQVPNNode responder{io};
    std::vector<uint8_t> initiator_id = std::vector<uint8_t>(32, 0x11);
    std::vector<uint8_t> responder_id = std::vector<uint8_t>(32, 0x22);
    asio::ip::udp::endpoint initiator_endpoint{asio::ip::make_address("127.0.0.1"), 9181};
    asio::ip::udp::endpoint responder_endpoint{asio::ip::make_address("127.0.0.1"), 9182};

    SinkHarness() {
        const std::vector<uint8_t> x_secret(32, 0x33);
        const std::vector<uint8_t> y_secret(32, 0x44);
        const std::vector<uint8_t> transcript{'S', 'I', 'N', 'K'};
        initiator.establish_hybrid_session(
            responder_id, responder_endpoint, x_secret, y_secret, transcript, true);
        responder.establish_hybrid_session(
            initiator_id, initiator_endpoint, x_secret, y_secret, transcript, false);
    }

    // Delivers one tunnel datagram to the responder and returns whether the
    // coroutine completed without an escaped exception.
    bool deliver(const std::vector<uint8_t>& packet) {
        auto datagram = initiator.build_tunnel_datagram(responder_id, std::span<const uint8_t>(packet));
        REQUIRE(datagram.has_value());
        std::exception_ptr failure;
        asio::co_spawn(io, responder.datagram_received(std::move(*datagram), initiator_endpoint),
            [&](std::exception_ptr e) {
                if (e) failure = std::move(e);
            });
        io.run();
        io.restart();
        return !failure;
    }
};

} // namespace

TEST_CASE("a throwing tunnel sink drops the frame but not the node", "[tunnel][resilience]") {
    SinkHarness h;
    int sink_calls = 0;
    std::vector<uint8_t> recovered;

    // The first call throws (adapter already closed); the second succeeds.
    h.responder.set_tunnel_packet_handler([&](std::vector<uint8_t> p) {
        ++sink_calls;
        if (sink_calls == 1) throw std::runtime_error("adapter is closed");
        recovered = std::move(p);
    });

    const std::vector<uint8_t> first{0x45, 0x00, 0x00, 0x14, 0xAA};
    REQUIRE(h.deliver(first)); // no exception escaped the coroutine
    REQUIRE(sink_calls == 1);  // sink was invoked and threw
    REQUIRE(recovered.empty()); // frame dropped

    const std::vector<uint8_t> second{0x60, 0x00, 0x00, 0x00, 0xBB};
    REQUIRE(h.deliver(second)); // node still processes traffic after the sink failure
    REQUIRE(sink_calls == 2);
    REQUIRE(recovered == second); // recovery: the next frame is delivered normally
}

TEST_CASE("adapter forwarding contains failures and recovers", "[tunnel][resilience]") {
    SinkHarness h;
    asio::ip::udp::socket socket(h.io, asio::ip::udp::endpoint(asio::ip::make_address("0.0.0.0"), 0));
    h.initiator.transport = &socket;

    // Poison the session so the build step refuses: nonce counter at its limit.
    auto& session = *h.initiator.sessions_by_peer_id.at(h.responder_id);
    session.nonce_send = std::numeric_limits<uint64_t>::max();

    bool result = true;
    std::exception_ptr failure;
    asio::co_spawn(h.io, h.initiator.forward_adapter_packet(std::vector<uint8_t>{0x45}),
        [&](std::exception_ptr e, bool ok) {
            if (e) {
                failure = std::move(e);
            } else {
                result = ok;
            }
        });
    h.io.run();
    h.io.restart(); // a stopped context would never run the next coroutine
    REQUIRE_FALSE(failure); // no escaped exception from the coroutine
    REQUIRE_FALSE(result);  // clean refusal

    // Recovery: a healthy session state forwards normally on the same context.
    session.nonce_send = 0;
    bool recovered = false;
    asio::co_spawn(h.io, h.initiator.forward_adapter_packet(std::vector<uint8_t>{0x46}),
        [&](std::exception_ptr e, bool ok) {
            if (!e) recovered = ok;
        });
    h.io.run();
    REQUIRE(recovered);
}
