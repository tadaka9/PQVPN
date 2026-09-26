// End-to-end egress test (the real user goal): client traffic enters node A,
// crosses the encrypted tunnel, is terminated by node B's user-space egress
// into a REAL socket, and the answer comes back through the tunnel to the
// client side. Everything runs with normal (non-elevated) permissions:
// loopback UDP for the tunnel, outbound connect() only for egress.
//
// Topology:
//   [client frame] -> ScriptedTap(A) -> A.forward_adapter_packet -> encrypted tunnel
//                     -> B decrypts -> EgressForwarder(B) -> real TCP socket -> HTTP server
//   answer:         HTTP server -> egress socket -> re-addressed frame -> tunnel
//                   -> A sink -> ScriptedTap outbox (the "client NIC")
//
// By default the "internet" is a scripted local HTTP/1.0 responder, so the test
// is deterministic and CI-safe. Setting PQVPN_E2E_WEB=host:port makes node B
// dial that real endpoint instead and asserts an actual HTTP response comes
// back through the tunnel (manual web-navigation check).

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "config_module.hpp"
#include "egress_forwarder.hpp"
#include "network_module.hpp"
#include "node_identity.hpp"
#include "node_module.hpp"
#include "platform/adapter.hpp"

using namespace pqvpn;
using namespace std::chrono_literals;

namespace {

// One node with its own io_context, UDP listener on loopback, and a freshly
// generated hybrid identity (same pattern as test_handshake_integration).
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
};

// Scripted TAP for node A: inject() pushes a frame into the tunnel path
// exactly like an adapter reader thread would; snapshot() returns everything
// that was delivered to the "client NIC" (the frames B sent back through the
// tunnel).
class ScriptedTap final : public platform::Adapter {
public:
    bool open(InboundHandler inbound) override {
        opened_ = static_cast<bool>(inbound);
        if (opened_) handler_ = std::move(inbound);
        return opened_;
    }
    bool write(const Packet& packet) noexcept override {
        std::lock_guard lock(mutex_);
        const auto before = outbox_.size();
        outbox_.push_back(packet);
        return outbox_.size() == before + 1; // the capture actually happened
    }
    void close() noexcept override {}
    bool is_open() const noexcept override { return opened_; }
    std::string describe() const override { return "scripted-tap (e2e)"; }

    void inject(const Packet& frame) {
        if (handler_) handler_(frame);
    }

    // Append-only log of delivered frames: predicates may re-scan it freely.
    std::vector<Packet> snapshot() const {
        std::lock_guard lock(mutex_);
        return outbox_;
    }

private:
    bool opened_ = false;
    InboundHandler handler_;
    mutable std::mutex mutex_;
    std::vector<Packet> outbox_;
};

struct TcpSeg {
    std::uint16_t flags = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::vector<uint8_t> payload;
};

bool parse_seg(const std::vector<uint8_t>& frame, TcpSeg& out) {
    if (frame.size() < 54 || static_cast<std::uint16_t>(frame[12] << 8 | frame[13]) != 0x0800) return false;
    const auto ihl = static_cast<std::size_t>(frame[14] & 0x0F) * 4u;
    if (ihl < 20 || frame.size() < 14 + ihl + 20) return false;
    const std::uint8_t* ip = frame.data() + 14;
    if (ip[9] != 6) return false;
    const auto total_len = static_cast<std::size_t>(static_cast<std::uint16_t>(ip[2] << 8 | ip[3]));
    if (total_len < ihl || total_len > frame.size() - 14) return false;
    const std::uint8_t* l4 = ip + ihl;
    out.flags = l4[13]; // single-byte flags field (the next byte is window hi)
    out.seq = (std::uint32_t(l4[4]) << 24) | (std::uint32_t(l4[5]) << 16) |
              (std::uint32_t(l4[6]) << 8) | std::uint32_t(l4[7]);
    out.ack = (std::uint32_t(l4[8]) << 24) | (std::uint32_t(l4[9]) << 16) |
              (std::uint32_t(l4[10]) << 8) | std::uint32_t(l4[11]);
    const auto dataoff = static_cast<std::size_t>(l4[12] >> 4) * 4u;
    if (dataoff < 20 || total_len < ihl + dataoff) return false;
    out.payload.assign(l4 + dataoff, l4 + (total_len - ihl));
    // Postcondition: extraction yielded exactly the declared segment bytes.
    return out.payload.size() == total_len - ihl - dataoff;
}

// Scripted HTTP/1.0 responder standing in for the internet: one connection,
// reads the request head, answers a fixed body, closes.
class LocalHttp {
public:
    explicit LocalHttp(asio::io_context& io) : acc_(io) {
        acc_.open(asio::ip::tcp::v4());
        acc_.set_option(asio::socket_base::reuse_address(true));
        acc_.bind({asio::ip::make_address("127.0.0.1"), 0});
        acc_.listen();
    }

    std::uint16_t port() const { return acc_.local_endpoint().port(); }

    void start() {
        auto conn = std::make_shared<asio::ip::tcp::socket>(acc_.get_executor());
        acc_.async_accept(*conn, [this, conn](const asio::error_code& ec) {
            if (ec) return;
            read_request(conn);
        });
    }

    bool served() const { return served_; }
    // Valid once served() is true (published by the atomic flag).
    const std::string& request() const { return request_; }

private:
    void read_request(std::shared_ptr<asio::ip::tcp::socket> sock) {
        auto buf = std::make_shared<std::string>();
        asio::async_read_until(*sock, asio::dynamic_buffer(*buf), "\r\n\r\n",
                               [this, sock, buf](const asio::error_code& ec, std::size_t n) {
            if (ec) return;
            request_.assign(buf->begin(), buf->begin() + static_cast<std::size_t>(n));
            // Static: the response buffer must outlive the async operation.
            static const std::string resp = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"
                                            "Connection: close\r\nContent-Length: 12\r\n\r\nPQVPN-E2E-OK";
            asio::async_write(
                *sock, asio::buffer(resp),
                [this, sock](const asio::error_code& wec, std::size_t /*written*/) {
                    if (!wec) served_ = true;
                asio::error_code cec;
                sock->shutdown(asio::socket_base::shutdown_type::shutdown_both, cec);
                sock->close(cec);
            });
        });
    }

    asio::ip::tcp::acceptor acc_;
    std::string request_;
    std::atomic<bool> served_{false};
};

} // namespace

TEST_CASE("egress e2e: client TCP crosses the tunnel and is terminated by a real socket",
          "[egress][e2e]") {
    TestNode a(29090);
    TestNode b(29091);
    const asio::ip::udp::endpoint ep_a(asio::ip::make_address("127.0.0.1"), 29090);
    const asio::ip::udp::endpoint ep_b(asio::ip::make_address("127.0.0.1"), 29091);

    // The "internet" endpoint: local scripted server by default, or a real
    // host via PQVPN_E2E_WEB=host:port for the manual web-navigation check.
    std::string target_host = "127.0.0.1";
    std::uint16_t target_port = 0;
    bool web_mode = false;
    if (const char* web = std::getenv("PQVPN_E2E_WEB")) {
        const auto colon = std::strrchr(web, ':');
        if (colon && colon != web) {
            target_host.assign(web, static_cast<std::size_t>(colon - web));
            target_port = static_cast<std::uint16_t>(std::atoi(colon + 1));
            web_mode = true;
        }
    }

    LocalHttp http(b.io); // only used in local mode
    if (!web_mode) {
        http.start();
        target_port = http.port();
    }

    // --- Node A: client side with a scripted TAP -----------------------------
    ScriptedTap tap_a;
    REQUIRE(tap_a.open([&a](ScriptedTap::Packet frame) {
        asio::co_spawn(a.io, a.node->forward_adapter_packet(std::move(frame)), asio::detached);
    }));
    // Frames B sends back through the tunnel land on the "client NIC".
    a.node->set_tunnel_packet_handler(
        [&tap_a](std::vector<uint8_t> frame, const std::vector<uint8_t>& /*src*/) { tap_a.write(frame); });

    // --- Node B: egress exit, no adapter (same wiring as main.cpp) ------------
    pqvpn::egress::EgressForwarder egress(b.io);
    auto* eg = &egress;
    egress.set_sender([&b](const std::vector<uint8_t>& frame, const std::vector<uint8_t>& peer) {
        if (peer.empty()) return false; // flow without a bound owner: fail closed
        return b.node->send_tunnel_packet(peer, std::span<const uint8_t>(frame));
    });
    std::atomic<int> leaked{0}; // frames that egress refused to consume
    b.node->set_tunnel_packet_handler(
        [&](std::vector<uint8_t> frame, const std::vector<uint8_t>& src) {
            if (eg->handle_frame(frame.data(), frame.size(), src)) return; // consumed by egress
            leaked++; // would have gone to a TAP we do not attach here
        });

    // --- Bootstrap + session upkeep, exactly like main.cpp --------------------
    asio::co_spawn(a.io, a.node->bootstrap_peers({ep_b}), asio::detached);
    asio::co_spawn(b.io, b.node->bootstrap_peers({ep_a}), asio::detached);
    asio::co_spawn(a.io, a.node->session_maintenance(), asio::detached);
    asio::co_spawn(b.io, b.node->session_maintenance(), asio::detached);

    std::thread runner_a([&] { a.io.run(); });
    std::thread runner_b([&] { b.io.run(); });
    const auto cleanup = [&] {
        a.io.stop();
        b.io.stop();
        if (runner_a.joinable()) runner_a.join();
        if (runner_b.joinable()) runner_b.join();
    };

    // Wait for both sides to report an established session.
    const auto deadline = std::chrono::steady_clock::now() + 30s;
    while (std::chrono::steady_clock::now() < deadline) {
        if (a.has_established_session_with(ep_b) && b.has_established_session_with(ep_a)) break;
        std::this_thread::sleep_for(100ms);
    }
    REQUIRE(a.has_established_session_with(ep_b));
    REQUIRE(b.has_established_session_with(ep_a));

    // --- Drive the client conversation (client sequence space) ----------------
    const pqvpn::egress::Mac client{{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
    const pqvpn::egress::Mac gateway{{0x02, 0x9c, 0x4a, 0x7b, 0x3d, 0xe5}}; // virtual egress MAC
    const auto c_ip = asio::ip::make_address("10.8.0.2");
    // make_address() only parses literals: resolve host names explicitly.
    std::error_code addr_ec;
    asio::ip::tcp::resolver resolver(a.io);
    const auto resolved = resolver.resolve(target_host, std::to_string(target_port), addr_ec);
    REQUIRE(!addr_ec);
    REQUIRE(!resolved.empty());
    const auto s_ip = resolved.begin()->endpoint().address();

    constexpr std::uint32_t ISN_C = 0x12345678u;
    using pqvpn::egress::build_tcp_frame;

    // 1) SYN with MSS option, like a real client stack.
    const std::vector<uint8_t> mss_opt = {2, 4, 0x05, 0xB4}; // MSS 1460
    tap_a.inject(build_tcp_frame(gateway, client, c_ip, s_ip, 54321, target_port, 0x02, ISN_C, 0,
                                 65535, mss_opt));

    // 2) The synthesized SYN-ACK must come back through the tunnel.
    TcpSeg syn_ack{};
    bool got_synack = false;
    const auto t1 = std::chrono::steady_clock::now() + 15s;
    while (!got_synack && std::chrono::steady_clock::now() < t1) {
        for (const auto& f : tap_a.snapshot()) {
            TcpSeg s;
            if (!parse_seg(f, s)) continue;
            if ((s.flags & 0x12) == 0x12 && s.ack == ISN_C + 1) { syn_ack = s; got_synack = true; break; }
        }
        std::this_thread::sleep_for(20ms);
    }
    REQUIRE(got_synack);
    const auto ISN_S = syn_ack.seq;

    // 3) Complete the handshake and send an HTTP request. Like a browser we
    // do NOT half-close before reading: some edges (e.g. Cloudflare) drop the
    // response when the client closes its send side first.
    tap_a.inject(build_tcp_frame(gateway, client, c_ip, s_ip, 54321, target_port, 0x10, ISN_C + 1,
                                 ISN_S + 1, 65535, {}));
    const std::string request = "GET / HTTP/1.0\r\nHost: " + target_host + "\r\n"
                                "User-Agent: PQVPN-E2E\r\nAccept: */*\r\n\r\n";
    tap_a.inject(build_tcp_frame(gateway, client, c_ip, s_ip, 54321, target_port, 0x18, ISN_C + 1,
                                 ISN_S + 1, 65535, {}, reinterpret_cast<const uint8_t*>(request.data()),
                                 request.size()));

    // 4) The answer must arrive as in-order data segments on the client NIC.
    std::string body;
    bool done = false;
    const auto t2 = std::chrono::steady_clock::now() + 15s;
    while (!done && std::chrono::steady_clock::now() < t2) {
        body.clear();
        for (const auto& f : tap_a.snapshot()) {
            TcpSeg s;
            if (!parse_seg(f, s)) continue;
            if ((s.flags & 0x12) == 0x12 && s.ack == ISN_C + 1) continue; // skip SYN-ACK
            if (s.payload.empty()) continue;                              // ACK/FIN only
            body.append(reinterpret_cast<const char*>(s.payload.data()), s.payload.size());
        }
        if (web_mode) {
            // A complete status line + header terminator proves the real
            // endpoint answered through the tunnel.
            done = body.rfind("HTTP/", 0) == 0 &&
                   body.find("\r\n\r\n") != std::string::npos;
        } else {
            done = body.find("PQVPN-E2E-OK") != std::string::npos;
        }
        std::this_thread::sleep_for(20ms);
    }
    cleanup();

    REQUIRE(done);
    if (!web_mode) {
        // The real socket on the exit node must have seen our exact request.
        REQUIRE(http.served());
        REQUIRE(http.request().rfind("GET / HTTP/1.0", 0) == 0);
        REQUIRE(body.rfind("HTTP/1.0 200 OK", 0) == 0);
    } else {
        // A real endpoint answered through the tunnel: any HTTP status line.
        std::cout << "e2e web check: " << target_host << ":" << target_port
                  << " -> " << body.substr(0, 64) << "\n";
    }

    // Nothing may have fallen through to a (nonexistent) adapter on node B.
    REQUIRE(leaked.load() == 0);
}