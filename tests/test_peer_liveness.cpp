#include <catch2/catch_test_macros.hpp>

#include <asio.hpp>
#include <chrono>
#include <cstdint>
#include <exception>
#include <vector>

#include "node_module.hpp"

namespace {

struct LivenessPair {
    asio::io_context io;
    pqvpn::PQVPNNode initiator{io};
    pqvpn::PQVPNNode responder{io};
    std::vector<uint8_t> initiator_id = std::vector<uint8_t>(32, 0x11);
    std::vector<uint8_t> responder_id = std::vector<uint8_t>(32, 0x22);
    asio::ip::udp::endpoint initiator_endpoint{asio::ip::make_address("127.0.0.1"), 9191};
    asio::ip::udp::endpoint responder_endpoint{asio::ip::make_address("127.0.0.1"), 9192};

    LivenessPair() {
        const std::vector<uint8_t> x_secret(32, 0x33);
        const std::vector<uint8_t> y_secret(32, 0x44);
        const std::vector<uint8_t> transcript{'P', 'Q', 'V', 'N', '-'};
        initiator.establish_hybrid_session(
            responder_id, responder_endpoint, x_secret, y_secret, transcript, true);
        responder.establish_hybrid_session(
            initiator_id, initiator_endpoint, x_secret, y_secret, transcript, false);
    }

    bool ping(pqvpn::PQVPNNode& node, const std::vector<uint8_t>& peer) {
        bool result = false;
        std::exception_ptr failure;
        asio::co_spawn(io, node.ping_tunnel_peer(peer),
            [&](std::exception_ptr e, bool ok) {
                if (e) {
                    failure = std::move(e);
                } else {
                    result = ok;
                }
            });
        io.run();
        // Restart the context: asio stops it once the work queue drains, and a
        // later co_spawn + run() on a stopped context would never execute.
        io.restart();
        REQUIRE_FALSE(failure);
        return result;
    }

    double now_seconds() const {
        return std::chrono::duration<double>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// Drive one maintenance pass and record completion. This must be a named
// coroutine function rather than a capturing lambda temporary passed to
// asio::co_spawn: GCC 15 on aarch64 miscompiles that pattern — the actor
// reads its captures from the original closure object after it has died
// (stack-use-after-scope / SIGSEGV at -O1 and above; passes at -O0, with
// GCC 14, and on x86_64). A named function's parameters are copied into
// its frame while the arguments are still alive.
asio::awaitable<void> drive_maintenance(pqvpn::PQVPNNode& node, bool& ticked) {
    co_await node.maintenance_tick();
    ticked = true;
}

} // namespace

TEST_CASE("tunnel ping elicits exactly one pong and refreshes liveness on both sides", "[tunnel][liveness]") {
    LivenessPair pair;
    asio::ip::udp::socket initiator_socket(pair.io, pair.initiator_endpoint);
    pair.initiator.transport = &initiator_socket;

    // Count every datagram each side receives: a PING must produce exactly one
    // PONG and nothing else (no loop, no spurious traffic).
    int initiator_datagrams = 0;
    int responder_datagrams = 0;

    asio::steady_timer deadline(pair.io, std::chrono::seconds(2));
    deadline.async_wait([&](const asio::error_code&) {
        initiator_socket.cancel();
    });

    std::vector<uint8_t> wire(65536);
    asio::ip::udp::endpoint from;
    // The responder must dispatch the PING into node processing so it can
    // answer; the initiator only counts what comes back.
    initiator_socket.async_receive_from(asio::buffer(wire), from,
        [&](const asio::error_code& ec, std::size_t) {
            if (!ec) {
                ++initiator_datagrams;
                deadline.cancel();
            }
        });

    asio::ip::udp::socket responder_socket(pair.io, pair.responder_endpoint);
    // The responder answers the PING through its own socket.
    pair.responder.transport = &responder_socket;
    std::vector<uint8_t> rwire(65536);
    asio::ip::udp::endpoint rfrom;
    responder_socket.async_receive_from(asio::buffer(rwire), rfrom,
        [&](const asio::error_code& ec, std::size_t n) {
            if (ec) return;
            ++responder_datagrams;
            auto datagram = std::vector<uint8_t>(rwire.begin(), rwire.begin() + static_cast<std::ptrdiff_t>(n));
            asio::co_spawn(pair.io, pair.responder.datagram_received(std::move(datagram), rfrom),
                asio::detached);
        });

    REQUIRE(pair.ping(pair.initiator, pair.responder_id));

    // The exchange must complete within the deadline: one PING out, one PONG back.
    REQUIRE(initiator_datagrams == 1);
    REQUIRE(responder_datagrams == 1);

    const double now = pair.now_seconds();
    auto& initiator_session = *pair.initiator.sessions_by_peer_id.at(pair.responder_id);
    auto& responder_session = *pair.responder.sessions_by_peer_id.at(pair.initiator_id);
    // The PONG refreshed the initiator's view of its peer...
    REQUIRE(now - initiator_session.last_peer_response < 5.0);
    // ...and the PING refreshed the responder's view of its peer.
    REQUIRE(now - responder_session.last_peer_response < 5.0);
}

TEST_CASE("peer selection excludes sessions without a recent peer response", "[tunnel][liveness]") {
    LivenessPair pair;
    const std::vector<uint8_t> stale_id(32, 0x41);
    const std::vector<uint8_t> live_id(32, 0x42);
    const std::vector<uint8_t> x_secret(32, 0x33);
    const std::vector<uint8_t> y_secret(32, 0x44);

    pair.initiator.establish_hybrid_session(
        stale_id, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9193),
        x_secret, y_secret, std::vector<uint8_t>{'S', 'T'}, true);
    pair.initiator.establish_hybrid_session(
        live_id, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9194),
        x_secret, y_secret, std::vector<uint8_t>{'L', 'V'}, false);

    auto& stale_session = *pair.initiator.sessions_by_peer_id.at(stale_id);
    auto& live_session = *pair.initiator.sessions_by_peer_id.at(live_id);

    // The silent peer is the most recently active one: activity alone must not
    // be enough to win selection.
    stale_session.last_activity += 100.0;
    stale_session.last_peer_response -= pqvpn::PQVPNNode::LIVENESS_WINDOW + 60.0;

    REQUIRE(pair.initiator.select_tunnel_peer() == live_id);
}

TEST_CASE("adapter forwarding fails closed when every tunnel peer is silent", "[tunnel][liveness]") {
    LivenessPair pair;
    asio::ip::udp::socket socket(pair.io, asio::ip::udp::endpoint(asio::ip::make_address("0.0.0.0"), 0));
    pair.initiator.transport = &socket;

    auto& session = *pair.initiator.sessions_by_peer_id.at(pair.responder_id);
    session.last_peer_response -= pqvpn::PQVPNNode::LIVENESS_WINDOW + 60.0;

    REQUIRE_FALSE(pair.initiator.select_tunnel_peer().has_value());

    bool forwarded = false;
    std::exception_ptr failure;
    asio::co_spawn(pair.io, pair.initiator.forward_adapter_packet(std::vector<uint8_t>{0x45, 0x00}),
        [&](std::exception_ptr e, bool ok) {
            if (e) {
                failure = std::move(e);
            } else {
                forwarded = ok;
            }
        });
    pair.io.run();
    REQUIRE_FALSE(failure);
    REQUIRE_FALSE(forwarded);
}

TEST_CASE("a fresh session is selectable before its first liveness round trip", "[tunnel][liveness]") {
    LivenessPair pair;
    // No PING/PONG has flown yet, but the session was just established: it must
    // not be dropped by selection during the grace window.
    REQUIRE(pair.initiator.select_tunnel_peer() == pair.responder_id);
}

TEST_CASE("liveness builder refuses frame types outside the PING/PONG contract", "[tunnel][liveness]") {
    LivenessPair pair;
    auto& session = *pair.initiator.sessions_by_peer_id.at(pair.responder_id);

    // The type guard must hold even for a fully healthy, established session:
    // no other frame type may be minted as an authenticated empty-plaintext
    // liveness frame.
    for (const uint8_t type : {pqvpn::PQVPNNode::DATA_FRAME,
                              pqvpn::PQVPNNode::TUNNEL_DATA_FRAME,
                              pqvpn::PQVPNNode::RELAY_FRAME}) {
        REQUIRE_FALSE(pair.initiator.build_tunnel_liveness_frame(type, session).has_value());
    }

    // The two liveness constants remain buildable on the same healthy session,
    // with the exact header(16) + nonce(12) + tag(16) shape.
    const auto ping = pair.initiator.build_tunnel_liveness_frame(pqvpn::PQVPNNode::TUNNEL_PING, session);
    REQUIRE(ping.has_value());
    REQUIRE(ping->size() == 44);
    REQUIRE(pair.initiator.build_tunnel_liveness_frame(pqvpn::PQVPNNode::TUNNEL_PONG, session).has_value());

    // The type guard is not what protects a broken session: with no AEAD send
    // key the liveness types fail closed too.
    const auto saved_key = session.aead_send_key;
    session.aead_send_key.clear();
    REQUIRE_FALSE(pair.initiator.build_tunnel_liveness_frame(pqvpn::PQVPNNode::TUNNEL_PING, session).has_value());
    session.aead_send_key = std::move(saved_key);
}

TEST_CASE("maintenance probes rescue a session idled past the liveness window", "[tunnel][liveness]") {
    LivenessPair pair;
    asio::ip::udp::socket initiator_socket(pair.io, pair.initiator_endpoint);
    pair.initiator.transport = &initiator_socket;

    auto& session = *pair.initiator.sessions_by_peer_id.at(pair.responder_id);
    // The session has been idle past LIVENESS_WINDOW (but well inside the
    // SESSION_TIMEOUT prune horizon): selection must exclude it...
    session.last_peer_response -= pqvpn::PQVPNNode::LIVENESS_WINDOW + 60.0;
    REQUIRE_FALSE(pair.initiator.select_tunnel_peer().has_value());

    // ...until the production maintenance loop probes and the peer answers.
    asio::ip::udp::socket responder_socket(pair.io, pair.responder_endpoint);
    pair.responder.transport = &responder_socket;

    asio::steady_timer deadline(pair.io, std::chrono::seconds(2));
    deadline.async_wait([&](const asio::error_code&) {
        initiator_socket.cancel();
        responder_socket.cancel();
    });

    std::vector<uint8_t> rwire(65536);
    asio::ip::udp::endpoint rfrom;
    // Register every receive before any send: one io.run() must cover the whole
    // probe/answer exchange (MinGW/Asio does not process queued work later).
    responder_socket.async_receive_from(asio::buffer(rwire), rfrom,
        [&](const asio::error_code& ec, std::size_t n) {
            if (ec) return;
            auto datagram = std::vector<uint8_t>(rwire.begin(), rwire.begin() + static_cast<std::ptrdiff_t>(n));
            asio::co_spawn(pair.io, pair.responder.datagram_received(std::move(datagram), rfrom),
                asio::detached);
        });

    bool pong_seen = false;
    std::vector<uint8_t> wire(65536);
    asio::ip::udp::endpoint from;
    // The production listener dispatches every received datagram into node
    // processing; the PONG must go through that real path to refresh liveness.
    initiator_socket.async_receive_from(asio::buffer(wire), from,
        [&](const asio::error_code& ec, std::size_t n) {
            if (ec) return;
            pong_seen = true;
            deadline.cancel();
            auto datagram = std::vector<uint8_t>(wire.begin(), wire.begin() + static_cast<std::ptrdiff_t>(n));
            asio::co_spawn(pair.io, pair.initiator.datagram_received(std::move(datagram), from),
                asio::detached);
        });

    bool ticked = false;
    std::exception_ptr failure;
    asio::co_spawn(pair.io, drive_maintenance(pair.initiator, ticked),
        [&](std::exception_ptr e) { if (e) failure = e; });

    pair.io.run();

    REQUIRE_FALSE(failure);
    REQUIRE(ticked);
    REQUIRE(pong_seen); // the probe reached the peer and it answered
    // The PONG refreshed liveness: the same session is selectable again.
    const double now = std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    REQUIRE(now - pair.initiator.sessions_by_peer_id.at(pair.responder_id)->last_peer_response < 5.0);
    REQUIRE(pair.initiator.select_tunnel_peer() == pair.responder_id);
}

TEST_CASE("unanswered probes do not extend session lifetime", "[tunnel][liveness]") {
    LivenessPair pair;
    asio::ip::udp::socket initiator_socket(pair.io, pair.initiator_endpoint);
    pair.initiator.transport = &initiator_socket;
    // The responder socket is bound so the local UDP handoff succeeds, but it
    // never dispatches: no PONG comes back and nothing refreshes liveness.
    asio::ip::udp::socket responder_sink(pair.io, pair.responder_endpoint);

    auto& session = *pair.initiator.sessions_by_peer_id.at(pair.responder_id);
    const double aged =
        session.last_activity - (pqvpn::PQVPNNode::SESSION_TIMEOUT + 60.0);
    session.last_activity = aged; // idle past the prune horizon

    REQUIRE(pair.ping(pair.initiator, pair.responder_id)); // local send succeeds
    REQUIRE(session.bytes_sent > 0);                        // outbound accounting kept
    // A successful UDP handoff is not proof of life: freshness must stay stale...
    REQUIRE(session.last_activity == aged);
    // ...so the next maintenance pass prunes the silent session instead of
    // keeping it alive forever.
    bool ticked = false;
    std::exception_ptr failure;
    asio::co_spawn(pair.io, drive_maintenance(pair.initiator, ticked),
        [&](std::exception_ptr e) { if (e) failure = e; });
    pair.io.run();

    REQUIRE_FALSE(failure);
    REQUIRE(ticked);
    REQUIRE(pair.initiator.sessions_by_peer_id.find(pair.responder_id)
            == pair.initiator.sessions_by_peer_id.end());
}

TEST_CASE("maintenance never swaps keys unilaterally when the rekey threshold is reached", "[tunnel][liveness]") {
    LivenessPair pair;
    auto& session = *pair.initiator.sessions_by_peer_id.at(pair.responder_id);

    // Force the rotation threshold (well past the 1MB traffic limit)...
    session.bytes_sent = 4ull * 1024 * 1024;
    const auto send_key_before = session.aead_send_key;
    const auto recv_key_before = session.aead_recv_key;
    const auto iv_before = session.session_iv;

    // ...and drive one full maintenance pass (no transport: the liveness probe
    // fails gracefully, which must not matter here).
    bool ticked = false;
    std::exception_ptr failure;
    asio::co_spawn(pair.io, drive_maintenance(pair.initiator, ticked),
        [&](std::exception_ptr e) { if (e) failure = e; });
    pair.io.run();

    REQUIRE_FALSE(failure);
    REQUIRE(ticked);
    // The authenticated channel must be intact: perform_rekey derives keys
    // from local entropy the peer cannot know, so a unilateral swap would
    // destroy every later frame. Keeping the working keys is the contract.
    REQUIRE(session.aead_send_key == send_key_before);
    REQUIRE(session.aead_recv_key == recv_key_before);
    REQUIRE(session.session_iv == iv_before);
}
