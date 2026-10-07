#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <iostream>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "egress_forwarder.hpp"

namespace {

using pqvpn::egress::Mac;

const Mac kClientMac{{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};
const Mac kEgressMacExpected{{0x02, 0x9c, 0x4a, 0x7b, 0x3d, 0xe5}};

std::uint16_t r_u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
std::uint32_t r_u32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

// One's-complement check: summing every 16-bit word of the covered region,
// including the stored checksum field, must yield 0xFFFF.
bool ones_complement_ok(const std::uint8_t* data, std::size_t len) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        sum += static_cast<std::uint32_t>((static_cast<std::uint16_t>(data[i]) << 8) | data[i + 1]);
    }
    if (len & 1u) sum += static_cast<std::uint32_t>(data[len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (sum & 0xFFFFu) == 0xFFFFu;
}

bool tcp_checksum_ok(const std::uint8_t* frame, std::size_t len) {
    const auto ihl = static_cast<std::size_t>(frame[14] & 0x0F) * 4u; // IP header at offset 14
    if (len < 14 + ihl + 20) return false;
    const std::uint8_t* ip = frame + 14;
    const auto total_len = r_u16(ip + 2);
    if (total_len < ihl || static_cast<std::size_t>(total_len) > len - 14) return false;
    const std::uint8_t* l4 = ip + ihl;
    const std::size_t l4_len = static_cast<std::size_t>(total_len) - ihl;

    // Pseudo-header (src+dst+proto+len) + transport (checksum field included).
    std::uint32_t sum = 0;
    auto add16 = [&sum](std::uint16_t v) { sum += v; };
    const auto s_nbo = r_u32(ip + 12);
    const auto d_nbo = r_u32(ip + 16);
    add16(static_cast<std::uint16_t>(s_nbo >> 16));
    add16(static_cast<std::uint16_t>(s_nbo & 0xFFFFu));
    add16(static_cast<std::uint16_t>(d_nbo >> 16));
    add16(static_cast<std::uint16_t>(d_nbo & 0xFFFFu));
    sum += ip[9];
    add16(static_cast<std::uint16_t>(total_len - ihl)); // L4 length field
    for (std::size_t i = 0; i + 1 < l4_len; i += 2) {
        sum += static_cast<std::uint32_t>((static_cast<std::uint16_t>(l4[i]) << 8) | l4[i + 1]);
    }
    if (l4_len & 1u) sum += static_cast<std::uint32_t>(l4[l4_len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (sum & 0xFFFFu) == 0xFFFFu;
}

bool udp_checksum_ok(const std::uint8_t* frame, std::size_t len) {
    const auto ihl = static_cast<std::size_t>(frame[14] & 0x0F) * 4u;
    if (len < 14 + ihl + 8) return false;
    const std::uint8_t* ip = frame + 14;
    const auto total_len = r_u16(ip + 2);
    if (total_len < ihl || static_cast<std::size_t>(total_len) > len - 14) return false;
    const std::uint8_t* l4 = ip + ihl;
    const std::size_t l4_len = static_cast<std::size_t>(total_len) - ihl;

    // Pseudo-header (src+dst+proto+len) + transport (checksum field included).
    std::uint32_t sum = 0;
    auto add16 = [&sum](std::uint16_t v) { sum += v; };
    const auto s_nbo = r_u32(ip + 12);
    const auto d_nbo = r_u32(ip + 16);
    add16(static_cast<std::uint16_t>(s_nbo >> 16));
    add16(static_cast<std::uint16_t>(s_nbo & 0xFFFFu));
    add16(static_cast<std::uint16_t>(d_nbo >> 16));
    add16(static_cast<std::uint16_t>(d_nbo & 0xFFFFu));
    sum += ip[9];
    add16(static_cast<std::uint16_t>(total_len - ihl)); // L4 length field
    for (std::size_t i = 0; i + 1 < l4_len; i += 2) {
        sum += static_cast<std::uint32_t>((static_cast<std::uint16_t>(l4[i]) << 8) | l4[i + 1]);
    }
    if (l4_len & 1u) sum += static_cast<std::uint32_t>(l4[l4_len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (sum & 0xFFFFu) == 0xFFFFu;
}

struct TcpSegment {
    std::uint16_t flags = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::vector<uint8_t> payload;
};

// Family-aware: accepts both IPv4 (0x0800) and IPv6 (0x86DD) TCP frames.
bool parse_tcp_segment(const std::vector<uint8_t>& frame, TcpSegment& out) {
    const auto ethertype = r_u16(frame.data() + 12);
    const std::uint8_t* l4 = nullptr;
    std::size_t seg_len = 0; // transport segment length (header + payload)
    if (ethertype == 0x0800) {
        if (frame.size() < 54) return false;
        const auto ihl = static_cast<std::size_t>(frame[14] & 0x0F) * 4u;
        if (ihl < 20 || frame.size() < 14 + ihl + 20) return false;
        const std::uint8_t* ip = frame.data() + 14;
        if (ip[9] != 6) return false;
        const auto total_len = r_u16(ip + 2);
        if (total_len < ihl || static_cast<std::size_t>(total_len) > frame.size() - 14)
            return false;
        l4 = ip + ihl;
        seg_len = static_cast<std::size_t>(total_len) - ihl;
    } else if (ethertype == 0x86DD) {
        if (frame.size() < 74) return false; // eth(14) + v6(40) + tcp(20)
        const std::uint8_t* ip = frame.data() + 14;
        if ((ip[0] >> 4) != 6 || ip[6] != 6) return false;
        seg_len = r_u16(ip + 4);
        if (seg_len < 20 || seg_len > frame.size() - 54) return false;
        l4 = ip + 40;
    } else {
        return false;
    }
    // The flags field is a single byte (offset 13); the next byte is the
    // high half of the window, so it must not be folded into `flags`.
    out.flags = l4[13];
    out.seq = r_u32(l4 + 4);
    out.ack = r_u32(l4 + 8);
    const auto dataoff = static_cast<std::size_t>(l4[12] >> 4) * 4u;
    if (dataoff < 20 || seg_len < dataoff) return false;
    // The payload runs from the end of the fixed header to the END of the
    // segment (`seg_len` is measured from l4, not from the payload start).
    out.payload.assign(l4 + dataoff, l4 + seg_len);
    // Postcondition: extraction yielded exactly the declared segment bytes.
    return out.payload.size() == seg_len - dataoff;
}

struct UdpDatagram {
    asio::ip::address src_addr; // v4 or v6, as on the wire
    asio::ip::address dst_addr;
    std::uint16_t sport = 0; // host order
    std::uint16_t dport = 0; // host order
    std::vector<uint8_t> payload;
};

// Family-aware: accepts both IPv4 (0x0800) and IPv6 (0x86DD) UDP frames.
bool parse_udp_datagram(const std::vector<uint8_t>& frame, UdpDatagram& out) {
    const auto ethertype = r_u16(frame.data() + 12);
    const std::uint8_t* l4 = nullptr;
    if (ethertype == 0x0800) {
        if (frame.size() < 42) return false;
        const auto ihl = static_cast<std::size_t>(frame[14] & 0x0F) * 4u;
        if (ihl < 20 || frame.size() < 14 + ihl + 8) return false;
        const std::uint8_t* ip = frame.data() + 14;
        if (ip[9] != 17) return false;
        const auto total_len = r_u16(ip + 2);
        if (total_len < ihl || static_cast<std::size_t>(total_len) > frame.size() - 14)
            return false;
        out.src_addr = asio::ip::address_v4(r_u32(ip + 12));
        out.dst_addr = asio::ip::address_v4(r_u32(ip + 16));
        l4 = ip + ihl;
    } else if (ethertype == 0x86DD) {
        if (frame.size() < 54) return false;
        const std::uint8_t* ip = frame.data() + 14;
        if ((ip[0] >> 4) != 6 || ip[6] != 17) return false;
        const auto payload_len = r_u16(ip + 4);
        if (payload_len < 8 || static_cast<std::size_t>(payload_len) > frame.size() - 54)
            return false;
        auto from_bytes_v6 = [](const std::uint8_t* p) {
            asio::ip::address_v6::bytes_type b{};
            std::copy_n(p, 16, b.begin());
            return asio::ip::address(asio::ip::address_v6(b));
        };
        out.src_addr = from_bytes_v6(ip + 8);
        out.dst_addr = from_bytes_v6(ip + 24);
        l4 = ip + 40;
    } else {
        return false;
    }
    out.sport = r_u16(l4);
    out.dport = r_u16(l4 + 2);
    const auto udp_len = r_u16(l4 + 4);
    if (udp_len < 8) return false;
    out.payload.assign(l4 + 8, l4 + udp_len);
    // Postcondition: extraction yielded exactly the declared datagram bytes.
    return out.payload.size() == static_cast<std::size_t>(udp_len) - 8u;
}

// Runs the io_context in small slices until `pred` holds or the deadline hits.
template <typename Pred>
bool wait_until(asio::io_context& io, int deadline_ms, Pred&& pred) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(deadline_ms);
    while (std::chrono::steady_clock::now() < end && !pred()) {
        io.run_for(std::chrono::milliseconds(10));
    }
    return pred();
}

struct Harness {
    asio::io_context io;
    std::vector<std::vector<uint8_t>> sent; // frames the forwarder pushed "through the tunnel"
    std::vector<std::vector<uint8_t>> sent_peers; // owning peer of each captured frame
    pqvpn::egress::EgressForwarder fwd{io};

    Harness() {
        fwd.set_sender([this](const std::vector<uint8_t>& frame, const std::vector<uint8_t>& peer) {
            const auto before = sent.size();
            sent.push_back(frame);
            sent_peers.push_back(peer);
            return sent.size() == before + 1; // the capture actually happened
        });
    }

    bool feed(const std::vector<uint8_t>& frame,
              const std::vector<uint8_t>& peer = {0xAB}) {
        return fwd.handle_frame(frame.data(), frame.size(), peer);
    }
};

} // namespace

TEST_CASE("built TCP and UDP frames carry valid checksums", "[egress][checksums]") {
    const Mac dst{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
    const Mac src{{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};

    const char* hello = "hello-egress";
    std::vector<uint8_t> payload(reinterpret_cast<const uint8_t*>(hello),
                                 reinterpret_cast<const uint8_t*>(hello) + 12);
    const auto src_ip = asio::ip::make_address("93.184.216.34");
    const auto dst_ip = asio::ip::make_address("10.8.0.2");

    std::vector<uint8_t> tcp_frame = pqvpn::egress::build_tcp_frame(
        dst, src, src_ip, dst_ip, 443, 54321, 0x18, 0x11223344u, 0x55667788u, 65535, {},
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size());
    REQUIRE(tcp_frame.size() == 14 + 20 + 20 + payload.size());
    REQUIRE(r_u16(tcp_frame.data() + 12) == 0x0800);
    REQUIRE(ones_complement_ok(tcp_frame.data() + 14, 20)); // IP header checksum
    REQUIRE(tcp_checksum_ok(tcp_frame.data(), tcp_frame.size()));

    std::vector<uint8_t> udp_frame = pqvpn::egress::build_udp_frame(
        dst, src, src_ip, dst_ip, 53, 54321, reinterpret_cast<const std::uint8_t*>(payload.data()),
        payload.size());
    REQUIRE(udp_frame.size() == 14 + 20 + 8 + payload.size());
    REQUIRE(ones_complement_ok(udp_frame.data() + 14, 20));
    REQUIRE(udp_checksum_ok(udp_frame.data(), udp_frame.size()));

    // The payload must round-trip intact.
    const auto* tail = tcp_frame.data() + tcp_frame.size() - payload.size();
    REQUIRE(std::memcmp(tail, payload.data(), payload.size()) == 0);
}

TEST_CASE("UDP relay bridges datagrams to a local server and re-addresses replies", "[egress][udp]") {
    Harness h;

    // Local echo server standing in for the internet.
    asio::ip::udp::socket server(h.io, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto port = server.local_endpoint().port();
    std::vector<uint8_t> echo_buf(65536);
    asio::ip::udp::endpoint from;
    std::function<void()> arm_echo;
    arm_echo = [&]() {
        server.async_receive_from(asio::buffer(echo_buf), from, [&](const asio::error_code& ec,
                                                                      std::size_t n) {
            if (ec) return;
            const char* pong = "pong:";
            std::vector<uint8_t> reply(reinterpret_cast<const uint8_t*>(pong),
                                       reinterpret_cast<const uint8_t*>(pong) + 5);
            reply.insert(reply.end(), echo_buf.begin(), echo_buf.begin() + static_cast<long>(n));
            asio::error_code send_ec;
            server.send_to(asio::buffer(reply), from, 0, send_ec);
            arm_echo();
        });
    };
    arm_echo();

    // Client datagram: 10.8.0.2:54321 -> 127.0.0.1:<port>.
    const auto c_addr = asio::ip::make_address("10.8.0.2");
    const auto srv_addr = asio::ip::make_address("127.0.0.1");
    const char* ping = "ping-egress";
    std::vector<uint8_t> payload(reinterpret_cast<const uint8_t*>(ping),
                                 reinterpret_cast<const uint8_t*>(ping) + 11);
    const Mac client{kClientMac};
    const Mac egress{kEgressMacExpected};
    auto frame = pqvpn::egress::build_udp_frame(
        egress, client, c_addr, srv_addr, 54321, port,
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size());

    REQUIRE(h.feed(frame));
    const bool got_reply = wait_until(h.io, 3000, [&] {
        bool matched = false;
        for (const auto& f : h.sent) {
            UdpDatagram d;
            if (!parse_udp_datagram(f, d)) continue;
            matched = d.sport == port && d.dport == 54321 && d.payload.size() >= 9;
            if (matched) break;
        }
        return matched;
    });
    REQUIRE(got_reply);

    UdpDatagram reply{};
    for (const auto& f : h.sent) {
        if (parse_udp_datagram(f, reply)) break;
    }
    REQUIRE(reply.src_addr == srv_addr); // from the "server"
    REQUIRE(reply.dst_addr == c_addr); // back to the client
    REQUIRE(reply.sport == port);
    REQUIRE(reply.dport == 54321);
    const std::string got(reinterpret_cast<const char*>(reply.payload.data()), reply.payload.size());
    REQUIRE(got == "pong:ping-egress");

    // The reply frame must be well-formed (checksums included).
    for (const auto& f : h.sent) {
        UdpDatagram d;
        if (parse_udp_datagram(f, d) && d.sport == port) {
            REQUIRE(udp_checksum_ok(f.data(), f.size()));
            break;
        }
    }
}

TEST_CASE("TCP flow synthesizes the handshake and bridges byte streams both ways", "[egress][tcp]") {
    Harness h;

    // Scripted server: read until EOF, then answer with a fixed body.
    asio::ip::tcp::acceptor acc(h.io);
    acc.open(asio::ip::tcp::v4());
    acc.set_option(asio::socket_base::reuse_address(true));
    acc.bind({asio::ip::make_address("127.0.0.1"), 0});
    acc.listen();
    const auto port = acc.local_endpoint().port();

    std::string server_received;
    bool server_answered = false;

    // The accepted socket must outlive the accept handler: a local socket in
    // that handler is destroyed (and resets the connection) when it returns.
    std::shared_ptr<asio::ip::tcp::socket> conn;
    std::function<void()> read_loop;
    read_loop = [&]() {
        auto buf = std::make_shared<std::vector<uint8_t>>(65536);
        auto keep = conn; // hold ownership for this operation's lifetime
        // `buf` must be captured by value (a copy of the shared_ptr): with a
        // plain `[&]` it would dangle as soon as read_loop returns, and the
        // first delivered byte would dereference freed storage.
        conn->async_read_some(asio::buffer(*buf),
                              [&, keep, buf](const asio::error_code& ec,
                                             std::size_t n) {
                                  if (ec == asio::error::eof) {
                                      // Answer now that the client half-closed.
                                      const char* body = "EGRESS-OK";
                                      asio::error_code w_ec;
                                      keep->write_some(asio::buffer(body, 9), w_ec);
                                      server_answered = true;
                                      return;
                                  }
                                  if (ec) return;
                                  server_received.append(buf->begin(),
                                                         buf->begin() + static_cast<long>(n));
                                  read_loop(); // keep reading
                              });
    };

    acc.async_accept([&](const asio::error_code& ec, asio::ip::tcp::socket sock) {
        if (ec) return;
        conn = std::make_shared<asio::ip::tcp::socket>(std::move(sock));
        read_loop();
    });

    const auto c_addr = asio::ip::make_address("10.8.0.2");
    const auto srv_addr = asio::ip::make_address("127.0.0.1");
    constexpr std::uint32_t ISN_C = 0x12345678u;
    const Mac client{kClientMac};
    const Mac egress{kEgressMacExpected};

    // 1) SYN with MSS option.
    std::vector<uint8_t> mss_opt = {2, 4, 0x05, 0xB4}; // MSS 1460
    auto syn = pqvpn::egress::build_tcp_frame(egress, client, c_addr, srv_addr, 54321, port, 0x02,
                                              ISN_C, 0, 65535, mss_opt);
    REQUIRE(h.feed(syn));

    // 2) Wait for the synthesized SYN-ACK.
    TcpSegment syn_ack{};
    bool found_synack = false;
    const bool got_synack = wait_until(h.io, 3000, [&] {
        for (const auto& f : h.sent) {
            TcpSegment s;
            if (!parse_tcp_segment(f, s)) continue;
            if ((s.flags & 0x12) == 0x12 && s.ack == ISN_C + 1) { syn_ack = s; found_synack = true; break; }
        }
        return found_synack;
    });
    REQUIRE(got_synack);
    const auto ISN_S = syn_ack.seq;

    // 3) ACK completing the (client-side) handshake.
    auto ack_seg = pqvpn::egress::build_tcp_frame(egress, client, c_addr, srv_addr, 54321, port,
                                                  0x10, ISN_C + 1, ISN_S + 1, 65535, {});
    REQUIRE(h.feed(ack_seg));

    // 4) Request bytes.
    const char* request = "EGRESS-REQUEST";
    auto data_seg = pqvpn::egress::build_tcp_frame(egress, client, c_addr, srv_addr, 54321, port,
                                                   0x18, ISN_C + 1, ISN_S + 1, 65535, {},
                                                   reinterpret_cast<const uint8_t*>(request), 14);
    REQUIRE(h.feed(data_seg));

    // 5) Half-close.
    auto fin_seg = pqvpn::egress::build_tcp_frame(egress, client, c_addr, srv_addr, 54321, port,
                                                  0x11, ISN_C + 15, ISN_S + 1, 65535, {});
    REQUIRE(h.feed(fin_seg));

    // 6) The server's answer must arrive as in-order segments in our sequence space.
    const bool got_body = wait_until(h.io, 4000, [&] {
        if (!server_answered) return false;
        std::string body; // rebuilt fresh on every poll (the predicate re-runs)
        for (const auto& f : h.sent) {
            TcpSegment s;
            if (!parse_tcp_segment(f, s)) continue;
            if ((s.flags & 0x12) == 0x12 && s.ack == ISN_C + 1) continue; // skip SYN-ACK
            if (s.payload.empty()) continue;                              // ACK/FIN only
            body.append(reinterpret_cast<const char*>(s.payload.data()), s.payload.size());
        }
        return body.find("EGRESS-OK") != std::string::npos;
    });
    REQUIRE(got_body);

    // Stream integrity: the server must have seen exactly our request bytes, in order.
    REQUIRE(server_received == "EGRESS-REQUEST");

    // Sequence consistency of every data segment we sent to the client.
    bool first = true;
    std::uint32_t expected_seq = ISN_S + 1;
    for (const auto& f : h.sent) {
        TcpSegment s;
        if (!parse_tcp_segment(f, s)) continue;
        if ((s.flags & 0x12) == 0x12 && s.ack == ISN_C + 1) continue; // SYN-ACK
        if (s.payload.empty()) continue;
        REQUIRE(s.seq == expected_seq);
        REQUIRE(s.ack == ISN_C + 15); // cumulative ACK of the full request (+FIN not yet acked)
        expected_seq += static_cast<std::uint32_t>(s.payload.size());
        first = false;
    }
    REQUIRE_FALSE(first);

    // Every data frame we emitted must be well-formed.
    for (const auto& f : h.sent) {
        TcpSegment s;
        if (!parse_tcp_segment(f, s)) continue;
        if (s.payload.empty()) continue;
        REQUIRE(tcp_checksum_ok(f.data(), f.size()));
    }
}

TEST_CASE("TCP connect failure resets the client flow", "[egress][tcp-refused]") {
    Harness h;

    // Reserve a port and release it so nothing is listening there.
    asio::ip::tcp::socket probe(h.io, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto closed_port = probe.local_endpoint().port();
    asio::error_code ec;
    probe.close(ec);

    const auto c_addr = asio::ip::make_address("10.8.0.2");
    const auto srv_addr = asio::ip::make_address("127.0.0.1");
    constexpr std::uint32_t ISN_C = 0x9A9B9C9Du;
    const Mac client{kClientMac};
    const Mac egress{kEgressMacExpected};

    auto syn = pqvpn::egress::build_tcp_frame(egress, client, c_addr, srv_addr, 54321, closed_port,
                                              0x02, ISN_C, 0, 65535, {});
    REQUIRE(h.feed(syn));

    bool found_rst = false;
    const bool got_rst = wait_until(h.io, 3000, [&] {
        for (const auto& f : h.sent) {
            TcpSegment s;
            if (!parse_tcp_segment(f, s)) continue;
            // RST|ACK
            found_rst = (s.flags & 0x14) == 0x14 && s.ack == ISN_C + 1;
            if (found_rst) break;
        }
        return found_rst;
    });
    REQUIRE(got_rst);
}

TEST_CASE("ARP requests are answered with a synthesized reply", "[egress][arp]") {
    Harness h;

    std::vector<uint8_t> frame;
    for (auto b : kEgressMacExpected.b) frame.push_back(b); // eth dst = egress
    for (auto b : kClientMac.b) frame.push_back(b);          // eth src = client
    frame.push_back(0x08);
    frame.push_back(0x06);

    auto put16 = [&frame](std::uint16_t v) {
        frame.push_back(static_cast<std::uint8_t>(v >> 8));
        frame.push_back(static_cast<std::uint8_t>(v & 0xFF));
    };
    auto put32 = [&frame](const std::string& ip) {
        const auto b = asio::ip::make_address(ip).to_v4().to_bytes();
        frame.insert(frame.end(), b.begin(), b.end());
    };
    put16(1);      // Ethernet
    put16(0x0800); // IPv4
    frame.push_back(6);
    frame.push_back(4);
    put16(1); // request
    for (auto b : kClientMac.b) frame.push_back(b);
    put32("10.8.0.2");
    frame.insert(frame.end(), 6, 0x00); // target MAC zeroed
    put32("10.8.0.1");                  // who-has the gateway?

    REQUIRE(h.feed(frame));

    const bool got_reply = wait_until(h.io, 1000, [&] { return !h.sent.empty(); });
    REQUIRE(got_reply);
    const auto& reply = h.sent.front();
    REQUIRE(reply.size() == 42);
    // Ethernet dst must be the client.
    for (int i = 0; i < 6; ++i) REQUIRE(reply[i] == kClientMac.b[i]);
    REQUIRE(r_u16(reply.data() + 12) == 0x0806);
    const std::uint8_t* a = reply.data() + 14;
    REQUIRE(r_u16(a + 6) == 2); // opcode: reply
    for (int i = 0; i < 6; ++i) REQUIRE(a[8 + i] == kEgressMacExpected.b[i]); // sender MAC = egress
    const auto claimed = asio::ip::address_v4(r_u32(a + 14));
    REQUIRE(claimed.to_string() == "10.8.0.1");
}

TEST_CASE("non-forwardable frames fall through to the legacy adapter write", "[egress][fallthrough]") {
    Harness h;

    // IPv4 with an unsupported protocol (GRE, proto 47): not egress's job.
    std::vector<uint8_t> gre = pqvpn::egress::build_udp_frame( // reuse builder shape for IP part
        kEgressMacExpected, kClientMac,
        asio::ip::make_address("10.8.0.2"),
        asio::ip::make_address("93.184.216.34"), 54321, 80,
        reinterpret_cast<const uint8_t*>("abcd"), 4);
    // Rewrite the protocol byte (the builder hardcodes UDP).
    gre[23] = 47;
    REQUIRE_FALSE(h.feed(gre));

    // Egress must not have created any flow.
    REQUIRE(h.fwd.flow_count() == 0);
}

TEST_CASE("ICMP echo to the virtual gateway is answered; other ICMP is consumed", "[egress][icmp]") {
    Harness h;

    // Echo request (type 8) from client 10.8.0.2 to the gateway 10.8.0.1,
    // id 0x1234, seq 7, with a payload.
    std::vector<uint8_t> msg = {8, 0, 0, 0, 0x12, 0x34, 0x00, 0x07}; // type code cksum id seq
    const char* data = "ping-gw";
    msg.insert(msg.end(), reinterpret_cast<const uint8_t*>(data),
               reinterpret_cast<const uint8_t*>(data) + 7);
    const auto cs = pqvpn::egress::checksum16(msg.data(), msg.size());
    msg[2] = static_cast<std::uint8_t>(cs >> 8);
    msg[3] = static_cast<std::uint8_t>(cs & 0xFF);

    // Ethernet + IPv4 (proto ICMP) + the raw ICMP message.
    auto build_icmp_frame = [&](const std::string& dst_ip) {
        std::vector<uint8_t> frame;
        for (auto b : kEgressMacExpected.b) frame.push_back(b);
        for (auto b : kClientMac.b) frame.push_back(b);
        frame.push_back(0x08);
        frame.push_back(0x00);
        std::vector<uint8_t> ip(20, 0);
        auto put16 = [](std::uint8_t* p, std::uint16_t v) {
            p[0] = static_cast<std::uint8_t>(v >> 8);
            p[1] = static_cast<std::uint8_t>(v & 0xFF);
        };
        ip[0] = 0x45;
        put16(ip.data() + 2, static_cast<std::uint16_t>(20 + msg.size()));
        put16(ip.data() + 4, 0x0102);
        ip[8] = 64;
        ip[9] = 1; // ICMP
        const auto cb = asio::ip::make_address("10.8.0.2").to_v4().to_bytes();
        std::copy(cb.begin(), cb.end(), ip.begin() + 12);
        const auto db = asio::ip::make_address(dst_ip).to_v4().to_bytes();
        std::copy(db.begin(), db.end(), ip.begin() + 16);
        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), msg.begin(), msg.end());
        return frame;
    };

    REQUIRE(h.feed(build_icmp_frame("10.8.0.1")));
    const bool got_reply = wait_until(h.io, 1000, [&] { return !h.sent.empty(); });
    REQUIRE(got_reply);
    const auto& reply = h.sent.front();
    REQUIRE(r_u16(reply.data() + 12) == 0x0800);
    REQUIRE(reply[23] == 1); // still ICMP
    const std::uint8_t* m = reply.data() + 34; // eth(14) + ip(20)
    REQUIRE(m[0] == 0);                        // echo REPLY, not request
    REQUIRE(r_u16(m + 4) == 0x1234);           // id preserved
    REQUIRE(r_u16(m + 6) == 7);                // seq preserved
    const std::string payload(reinterpret_cast<const char*>(m + 8), msg.size() - 8u);
    REQUIRE(payload == "ping-gw");             // data mirrored intact
    // Endpoints swapped: from the gateway, to the client.
    REQUIRE(asio::ip::address_v4(r_u32(reply.data() + 26)).to_string() == "10.8.0.1");
    REQUIRE(asio::ip::address_v4(r_u32(reply.data() + 30)).to_string() == "10.8.0.2");
    // The reply's ICMP checksum must verify (sum incl. stored field = 0xFFFF).
    REQUIRE(ones_complement_ok(m, msg.size()));

    // Echo to a foreign destination: consumed without any reply — forwarding
    // it would need raw sockets, which normal permissions do not grant.
    h.sent.clear();
    REQUIRE(h.feed(build_icmp_frame("93.184.216.34"))); // consumed by egress policy
    for (int i = 0; i < 5; ++i) h.io.run_for(std::chrono::milliseconds(20));
    REQUIRE(h.sent.empty()); // nothing was emitted for the foreign echo

    // Egress must not have created any flow.
    REQUIRE(h.fwd.flow_count() == 0);
}

TEST_CASE("IPv6 UDP relay bridges datagrams to a local v6 server", "[egress][ipv6]") {
    Harness h;

    // Local echo server on the IPv6 loopback, standing in for the internet.
    asio::ip::udp::socket server(h.io,
                                 asio::ip::udp::endpoint(asio::ip::make_address("::1"), 0));
    const auto port = server.local_endpoint().port();
    std::vector<uint8_t> echo_buf(65536);
    asio::ip::udp::endpoint from;
    std::function<void()> arm_echo;
    arm_echo = [&]() {
        server.async_receive_from(asio::buffer(echo_buf), from, [&](const asio::error_code& ec,
                                                                      std::size_t n) {
            if (ec) return;
            const char* pong = "v6:";
            std::vector<uint8_t> reply(reinterpret_cast<const uint8_t*>(pong),
                                       reinterpret_cast<const uint8_t*>(pong) + 3);
            reply.insert(reply.end(), echo_buf.begin(), echo_buf.begin() + static_cast<long>(n));
            asio::error_code send_ec;
            server.send_to(asio::buffer(reply), from, 0, send_ec);
            arm_echo();
        });
    };
    arm_echo();

    const auto c_addr = asio::ip::make_address("fd00::2"); // client's virtual v6 address
    const auto srv_addr = asio::ip::make_address("::1");
    const char* ping = "ping-v6";
    std::vector<uint8_t> payload(reinterpret_cast<const uint8_t*>(ping),
                                 reinterpret_cast<const uint8_t*>(ping) + 7);

    auto frame = pqvpn::egress::build_udp_frame(kEgressMacExpected, kClientMac, c_addr, srv_addr,
                                                54321, port,
                                                reinterpret_cast<const std::uint8_t*>(payload.data()),
                                                payload.size());
    REQUIRE(r_u16(frame.data() + 12) == 0x86DD); // sanity: the builder emitted IPv6
    REQUIRE(h.feed(frame));

    const bool got_reply = wait_until(h.io, 3000, [&] {
        for (const auto& f : h.sent) {
            UdpDatagram d;
            if (!parse_udp_datagram(f, d)) continue;
            // Matched the reply we are waiting for: report it.
            if (d.sport == port && d.dport == 54321)
                return d.dport == 54321;
        }
        return false;
    });
    REQUIRE(got_reply);

    UdpDatagram reply{};
    for (const auto& f : h.sent) {
        if (parse_udp_datagram(f, reply)) break;
    }
    REQUIRE(reply.src_addr == srv_addr); // from the v6 "server"
    REQUIRE(reply.dst_addr == c_addr); // back to the client's virtual address
    const std::string got(reinterpret_cast<const char*>(reply.payload.data()), reply.payload.size());
    REQUIRE(got == "v6:ping-v6");
}

TEST_CASE("IPv6 TCP flow synthesizes the handshake and bridges byte streams", "[egress][ipv6]") {
    Harness h;

    // Scripted server on [::1]: read until EOF, then answer with a fixed body.
    asio::ip::tcp::acceptor acc(h.io);
    acc.open(asio::ip::tcp::v6());
    acc.set_option(asio::socket_base::reuse_address(true));
    acc.bind({asio::ip::make_address("::1"), 0});
    acc.listen();
    const auto port = acc.local_endpoint().port();

    bool server_answered = false;
    std::shared_ptr<asio::ip::tcp::socket> conn;
    std::function<void()> read_loop;
    read_loop = [&]() {
        auto buf = std::make_shared<std::vector<uint8_t>>(65536);
        auto keep = conn; // hold ownership for this operation's lifetime
        conn->async_read_some(asio::buffer(*buf),
                              [&, keep, buf](const asio::error_code& ec, std::size_t n) {
                                  if (ec == asio::error::eof) {
                                      const char* body = "V6-OK";
                                      asio::error_code w_ec;
                                      keep->write_some(asio::buffer(body, 5), w_ec);
                                      server_answered = true;
                                      return;
                                  }
                                  if (ec) return;
                                  read_loop();
                              });
    };
    acc.async_accept([&](const asio::error_code& ec, asio::ip::tcp::socket sock) {
        if (ec) return;
        conn = std::make_shared<asio::ip::tcp::socket>(std::move(sock));
        read_loop();
    });

    const auto c_addr = asio::ip::make_address("fd00::2");
    const auto srv_addr = asio::ip::make_address("::1");
    constexpr std::uint32_t ISN_C = 0x600DF00Du;

    auto syn = pqvpn::egress::build_tcp_frame(kEgressMacExpected, kClientMac, c_addr, srv_addr,
                                              54321, port, 0x02, ISN_C, 0, 65535, {});
    REQUIRE(h.feed(syn));

    std::uint32_t isn_s = 0;
    const bool got_synack = wait_until(h.io, 3000, [&] {
        for (const auto& f : h.sent) {
            TcpSegment s;
            if (!parse_tcp_segment(f, s)) continue;
            if ((s.flags & 0x12) == 0x12 && s.ack == ISN_C + 1) { isn_s = s.seq; break; }
        }
        return isn_s != 0; // the egress ISN is non-zero by construction
    });
    REQUIRE(got_synack);

    auto ack_seg = pqvpn::egress::build_tcp_frame(kEgressMacExpected, kClientMac, c_addr, srv_addr,
                                                  54321, port, 0x10, ISN_C + 1, isn_s + 1, 65535,
                                                  {});
    REQUIRE(h.feed(ack_seg));

    const char* request = "V6-REQUEST";
    auto data_seg = pqvpn::egress::build_tcp_frame(kEgressMacExpected, kClientMac, c_addr, srv_addr,
                                                   54321, port, 0x18, ISN_C + 1, isn_s + 1, 65535,
                                                   {},
                                                   reinterpret_cast<const uint8_t*>(request), 10);
    REQUIRE(h.feed(data_seg));

    auto fin_seg = pqvpn::egress::build_tcp_frame(kEgressMacExpected, kClientMac, c_addr, srv_addr,
                                                  54321, port, 0x11, ISN_C + 11, isn_s + 1, 65535,
                                                  {});
    REQUIRE(h.feed(fin_seg));

    const bool got_body = wait_until(h.io, 4000, [&] {
        if (!server_answered) return false;
        std::string body;
        for (const auto& f : h.sent) {
            TcpSegment s;
            if (!parse_tcp_segment(f, s)) continue;
            if ((s.flags & 0x12) == 0x12 && s.ack == ISN_C + 1) continue; // skip SYN-ACK
            if (s.payload.empty()) continue;
            body.append(reinterpret_cast<const char*>(s.payload.data()), s.payload.size());
        }
        return body.find("V6-OK") != std::string::npos;
    });
    REQUIRE(got_body);
}

TEST_CASE("fragmented IPv4 UDP datagrams are reassembled before dispatch", "[egress][fragments]") {
    Harness h;

    // Local echo server standing in for the internet.
    asio::ip::udp::socket server(h.io, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto port = server.local_endpoint().port();
    std::vector<uint8_t> echo_buf(65536);
    asio::ip::udp::endpoint from;
    std::function<void()> arm_echo;
    arm_echo = [&]() {
        server.async_receive_from(asio::buffer(echo_buf), from, [&](const asio::error_code& ec,
                                                                      std::size_t n) {
            if (ec) return;
            const char* pong = "F:";
            std::vector<uint8_t> reply(reinterpret_cast<const uint8_t*>(pong),
                                       reinterpret_cast<const uint8_t*>(pong) + 2);
            reply.insert(reply.end(), echo_buf.begin(), echo_buf.begin() + static_cast<long>(n));
            asio::error_code send_ec;
            server.send_to(asio::buffer(reply), from, 0, send_ec);
            arm_echo();
        });
    };
    arm_echo();

    // The unfragmented UDP segment: header + a 15-byte payload.
    std::vector<uint8_t> l4(23, 0);
    auto put16 = [](std::uint8_t* p, std::uint16_t v) {
        p[0] = static_cast<std::uint8_t>(v >> 8);
        p[1] = static_cast<std::uint8_t>(v & 0xFF);
    };
    put16(l4.data(), 54321);
    put16(l4.data() + 2, port);
    put16(l4.data() + 4, static_cast<std::uint16_t>(l4.size()));
    const char* ping = "ping-fragments!"; // 15 bytes
    std::copy_n(ping, 15, l4.begin() + 8);

    // One fragment frame: Ethernet + IPv4 (shared id, proto UDP) + a piece of
    // the segment at `offset_bytes` (a multiple of 8), MF per `more`.
    auto build_frag = [&](std::size_t offset_bytes, bool more, const std::uint8_t* piece,
                          std::size_t n) {
        std::vector<uint8_t> frame;
        for (auto b : kEgressMacExpected.b) frame.push_back(b);
        for (auto b : kClientMac.b) frame.push_back(b);
        frame.push_back(0x08);
        frame.push_back(0x00);
        std::vector<uint8_t> ip(20, 0);
        ip[0] = 0x45;
        const auto total = static_cast<std::uint16_t>(20 + n);
        put16(ip.data() + 2, total);
        put16(ip.data() + 4, 0xABCD); // shared datagram id
        put16(ip.data() + 6,
              static_cast<std::uint16_t>((more ? 0x2000 : 0) | (offset_bytes / 8u)));
        ip[8] = 64;
        ip[9] = 17; // UDP
        const auto cb = asio::ip::make_address("10.8.0.2").to_v4().to_bytes();
        std::copy(cb.begin(), cb.end(), ip.begin() + 12);
        const auto db = asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
        std::copy(db.begin(), db.end(), ip.begin() + 16);
        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), piece, piece + n);
        return frame;
    };

    // Feed the LAST fragment first (out of order), then the first one.
    REQUIRE(h.feed(build_frag(8, false, l4.data() + 8, 15)));
    REQUIRE(h.feed(build_frag(0, true, l4.data(), 8)));

    const bool got_reply = wait_until(h.io, 3000, [&] {
        for (const auto& f : h.sent) {
            UdpDatagram d;
            if (!parse_udp_datagram(f, d) || d.sport != port) continue;
            const std::string got(reinterpret_cast<const char*>(d.payload.data()),
                                  d.payload.size());
            return got == "F:ping-fragments!"; // the WHOLE payload arrived upstream
        }
        return false;
    });
    REQUIRE(got_reply);
}

TEST_CASE("partial fragment reassemblies expire instead of accumulating", "[egress][fragments]") {
    Harness h;
    h.fwd.set_fragment_timeout(0.2); // 200 ms
    h.fwd.set_sweep_interval(std::chrono::milliseconds(50));

    // Echo server: if the stale first fragment were still around, completing
    // it would dispatch and produce a reply; after expiry there must be none.
    asio::ip::udp::socket server(h.io,
                                 asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto port = server.local_endpoint().port();
    std::vector<uint8_t> echo_buf(65536);
    asio::ip::udp::endpoint from;
    std::function<void()> arm_echo;
    arm_echo = [&]() {
        server.async_receive_from(asio::buffer(echo_buf), from, [&](const asio::error_code& ec,
                                                                      std::size_t n) {
            if (ec) return;
            const char* pong = "X:";
            std::vector<uint8_t> reply(reinterpret_cast<const uint8_t*>(pong),
                                       reinterpret_cast<const uint8_t*>(pong) + 2);
            reply.insert(reply.end(), echo_buf.begin(), echo_buf.begin() + static_cast<long>(n));
            asio::error_code send_ec;
            server.send_to(asio::buffer(reply), from, 0, send_ec);
            arm_echo();
        });
    };
    arm_echo();

    auto build_frag = [&](std::size_t offset_bytes, bool more, const std::uint8_t* piece,
                          std::size_t n) {
        std::vector<uint8_t> frame;
        for (auto b : kEgressMacExpected.b) frame.push_back(b);
        for (auto b : kClientMac.b) frame.push_back(b);
        frame.push_back(0x08);
        frame.push_back(0x00);
        std::vector<uint8_t> ip(20, 0);
        auto put16 = [](std::uint8_t* p, std::uint16_t v) {
            p[0] = static_cast<std::uint8_t>(v >> 8);
            p[1] = static_cast<std::uint8_t>(v & 0xFF);
        };
        ip[0] = 0x45;
        put16(ip.data() + 2, static_cast<std::uint16_t>(20 + n));
        put16(ip.data() + 4, 0x1234); // shared datagram id
        put16(ip.data() + 6,
              static_cast<std::uint16_t>((more ? 0x2000 : 0) | (offset_bytes / 8u)));
        ip[8] = 64;
        ip[9] = 17;
        const auto cb = asio::ip::make_address("10.8.0.2").to_v4().to_bytes();
        std::copy(cb.begin(), cb.end(), ip.begin() + 12);
        const auto db = asio::ip::make_address("127.0.0.1").to_v4().to_bytes();
        std::copy(db.begin(), db.end(), ip.begin() + 16);
        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), piece, piece + n);
        return frame;
    };

    // First fragment only; its partner never arrives in time.
    std::vector<uint8_t> head(8, 0x5A); // would be the UDP header
    REQUIRE(h.feed(build_frag(0, true, head.data(), 8)));

    // Let the deadline pass and the sweeper run at least once.
    for (int i = 0; i < 12; ++i) h.io.run_for(std::chrono::milliseconds(50));

    // Now the second fragment: with the stale entry gone it starts a fresh,
    // incomplete reassembly and must NOT be dispatched to the server.
    std::vector<uint8_t> tail(16, 0x7B);
    REQUIRE(h.feed(build_frag(8, false, tail.data(), 16)));

    for (int i = 0; i < 12; ++i) h.io.run_for(std::chrono::milliseconds(50));
    REQUIRE(h.sent.empty()); // no dispatch happened: the old entry had expired
}

TEST_CASE("one exit serves several clients: replies bind to the owning peer", "[egress][multi-client]") {
    Harness h;

    // Two local endpoints standing in for two distinct internet servers.
    asio::ip::udp::socket server_a(h.io, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto port_a = server_a.local_endpoint().port();
    std::vector<uint8_t> buf_a(65536);
    asio::ip::udp::endpoint from_a;
    std::function<void()> arm_a;
    arm_a = [&]() {
        server_a.async_receive_from(asio::buffer(buf_a), from_a, [&](const asio::error_code& ec,
                                                                      std::size_t n) {
            if (ec) return;
            const char* tag = "A:";
            std::vector<uint8_t> reply(reinterpret_cast<const uint8_t*>(tag),
                                       reinterpret_cast<const uint8_t*>(tag) + 2);
            reply.insert(reply.end(), buf_a.begin(), buf_a.begin() + static_cast<long>(n));
            asio::error_code send_ec;
            server_a.send_to(asio::buffer(reply), from_a, 0, send_ec);
            arm_a();
        });
    };
    arm_a();

    // Scripted TCP server for the second client: answer after half-close.
    asio::ip::tcp::acceptor acc_b(h.io);
    acc_b.open(asio::ip::tcp::v4());
    acc_b.set_option(asio::socket_base::reuse_address(true));
    acc_b.bind({asio::ip::make_address("127.0.0.1"), 0});
    acc_b.listen();
    const auto port_b = acc_b.local_endpoint().port();
    std::shared_ptr<asio::ip::tcp::socket> conn_b;
    std::function<void()> read_loop_b;
    read_loop_b = [&]() {
        auto buf = std::make_shared<std::vector<uint8_t>>(65536);
        auto keep = conn_b; // hold ownership for this operation's lifetime
        conn_b->async_read_some(asio::buffer(*buf),
                                [&, keep, buf](const asio::error_code& ec, std::size_t n) {
                                    if (ec == asio::error::eof) {
                                        const char* body = "B-RESPONSE";
                                        asio::error_code w_ec;
                                        keep->write_some(asio::buffer(body, 10), w_ec);
                                        return;
                                    }
                                    if (ec) return;
                                    read_loop_b();
                                });
    };
    acc_b.async_accept([&](const asio::error_code& ec, asio::ip::tcp::socket sock) {
        if (ec) return;
        conn_b = std::make_shared<asio::ip::tcp::socket>(std::move(sock));
        read_loop_b();
    });

    const Mac client{kClientMac};
    const Mac egress{kEgressMacExpected};
    const auto c_a_addr = asio::ip::make_address("10.8.0.2"); // peer A's virtual IP
    const auto c_b_addr = asio::ip::make_address("10.8.0.3"); // peer B's virtual IP
    const auto srv_addr = asio::ip::make_address("127.0.0.1");

    const std::vector<uint8_t> peer_a{0xAA};
    const std::vector<uint8_t> peer_b{0xBB};

    // Client A (peer {0xAA}): UDP datagram to server A.
    const char* ping_a = "ping-a";
    auto udp_a = pqvpn::egress::build_udp_frame(egress, client, c_a_addr, srv_addr, 54321, port_a,
                                                reinterpret_cast<const std::uint8_t*>(ping_a), 6);
    REQUIRE(h.feed(udp_a, peer_a));

    // Client B (peer {0xBB}): TCP handshake + request to server B.
    constexpr std::uint32_t ISN_B = 0x77AABBCCu;
    auto syn_b = pqvpn::egress::build_tcp_frame(egress, client, c_b_addr, srv_addr, 54322, port_b,
                                                 0x02, ISN_B, 0, 65535, {});
    REQUIRE(h.feed(syn_b, peer_b));

    // Complete B's client-side handshake once the synthesized SYN-ACK lands.
    std::uint32_t isn_b_s = 0;
    const bool got_synack_b = wait_until(h.io, 3000, [&] {
        for (const auto& f : h.sent) {
            TcpSegment s;
            if (!parse_tcp_segment(f, s)) continue;
            if ((s.flags & 0x12) == 0x12 && s.ack == ISN_B + 1) { isn_b_s = s.seq; break; }
        }
        return isn_b_s != 0; // the egress ISN is non-zero by construction
    });
    REQUIRE(got_synack_b);

    auto ack_b = pqvpn::egress::build_tcp_frame(egress, client, c_b_addr, srv_addr, 54322, port_b,
                                                 0x10, ISN_B + 1, isn_b_s + 1, 65535, {});
    REQUIRE(h.feed(ack_b, peer_b));

    const char* request_b = "B-REQUEST";
    auto data_b = pqvpn::egress::build_tcp_frame(egress, client, c_b_addr, srv_addr, 54322, port_b,
                                                  0x18, ISN_B + 1, isn_b_s + 1, 65535, {},
                                                  reinterpret_cast<const std::uint8_t*>(request_b), 9);
    REQUIRE(h.feed(data_b, peer_b));

    auto fin_b = pqvpn::egress::build_tcp_frame(egress, client, c_b_addr, srv_addr, 54322, port_b,
                                                 0x11, ISN_B + 10, isn_b_s + 1, 65535, {});
    REQUIRE(h.feed(fin_b, peer_b));

    // Wait until both replies have been emitted through the tunnel.
    const bool got_both = wait_until(h.io, 4000, [&] {
        bool udp_reply = false;
        bool tcp_body = false;
        for (const auto& f : h.sent) {
            UdpDatagram d;
            if (parse_udp_datagram(f, d) && d.sport == port_a && d.dport == 54321) udp_reply = true;
            TcpSegment s;
            if (parse_tcp_segment(f, s) && !s.payload.empty() &&
                std::string(reinterpret_cast<const char*>(s.payload.data()), s.payload.size())
                    .find("B-RESPONSE") != std::string::npos)
                tcp_body = true;
        }
        return udp_reply && tcp_body;
    });
    REQUIRE(got_both);

    // Every emitted frame must be bound to the peer that owns its flow, and
    // each client's bytes must come back uncorrupted (no cross-talk).
    bool saw_a = false;
    bool saw_b = false;
    for (std::size_t i = 0; i < h.sent.size(); ++i) {
        UdpDatagram d;
        if (parse_udp_datagram(h.sent[i], d) && d.sport == port_a) {
            REQUIRE(d.dst_addr == c_a_addr); // client A's virtual IP
            const std::string got(reinterpret_cast<const char*>(d.payload.data()), d.payload.size());
            REQUIRE(got == "A:ping-a");       // server A's bytes, not B's
            REQUIRE(h.sent_peers[i] == peer_a);
            saw_a = true;
            continue;
        }
        TcpSegment s;
        if (parse_tcp_segment(h.sent[i], s) && !s.payload.empty()) {
            const std::string body(reinterpret_cast<const char*>(s.payload.data()), s.payload.size());
            REQUIRE(body.find("B-RESPONSE") != std::string::npos); // server B's bytes, not A's
            REQUIRE(h.sent_peers[i] == peer_b);
            saw_b = true;
        }
    }
    REQUIRE(saw_a);
    REQUIRE(saw_b);

    // Both flows live on the same exit at once.
    REQUIRE(h.fwd.flow_count() >= 2);
}
