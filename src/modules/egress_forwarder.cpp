#include "egress_forwarder.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <random>
#include <vector>

#include "logging_module.hpp"

namespace pqvpn::egress {
namespace {

constexpr std::size_t kMaxPendingBytes = 1u << 20;    // client->server queue cap (1 MiB)
constexpr std::size_t kMaxOooEntries = 64;            // out-of-order segment cap
constexpr std::size_t kMaxServerBuffer = 1u << 17;    // un-delivered server bytes cap (128 KiB)
constexpr int32_t kMaxInFlightBytes = 256 * 1024;     // S->C backpressure window
constexpr double kTcpIdleTimeoutSeconds = 300.0;
constexpr double kUdpIdleTimeoutSeconds = 60.0;
constexpr std::size_t kMaxFlows = 512;

constexpr std::size_t kMaxFragmentEntries = 32;   // in-progress reassemblies
constexpr std::size_t kMaxReassemblyBytes = 65536; // per datagram (max IPv4 size)

constexpr std::uint16_t kFlagFin = 0x01;
constexpr std::uint16_t kFlagSyn = 0x02;
constexpr std::uint16_t kFlagRst = 0x04;
constexpr std::uint16_t kFlagAck = 0x10;

// Locally-administered unicast MAC presented to clients (ARP replies and the
// source of every return frame). Stable on purpose: it is the virtual gateway.
const Mac kEgressMac{{0x02, 0x9c, 0x4a, 0x7b, 0x3d, 0xe5}};

std::uint16_t ntohs_u(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
std::uint32_t ntohl_u(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

double now_seconds() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

void put_nbo16(std::vector<uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}
void put_nbo32(std::vector<uint8_t>& out, std::uint32_t v) {
    const auto b = asio::ip::address_v4(v).to_bytes(); // wire order on any endianness
    out.insert(out.end(), b.begin(), b.end());
}
// In-place variants for pre-sized header buffers.
void write_nbo16(std::uint8_t* out, std::uint16_t v) {
    out[0] = static_cast<std::uint8_t>(v >> 8);
    out[1] = static_cast<std::uint8_t>(v & 0xFF);
}
void write_nbo32(std::uint8_t* out, std::uint32_t v) {
    const auto b = asio::ip::address_v4(v).to_bytes();
    std::copy(b.begin(), b.end(), out);
}

std::uint32_t random_isn() {
    static std::mt19937 engine{std::random_device{}()};
    return (engine() & 0x7FFFFFFFu) + 1u; // non-zero, 31 bits
}

// Contract of EgressForwarder::handle_frame(): a positive result means the
// frame was consumed by egress policy — forwarded upstream, answered (ARP),
// or explicitly dropped as malformed/unsupported. A negative result means it
// is not forwardable and must fall through to the legacy adapter write.
// kConsumed names that positive outcome at each decision point.
constexpr bool kConsumed = true;

// Ethernet-II + one IP header (v4 or v6, chosen from the address family) +
// the transport segment. Both addresses must belong to the same family.
std::vector<uint8_t> build_ip_frame(const Mac& dst, const Mac& src,
                                    const asio::ip::address& srv_addr,
                                    const asio::ip::address& d_addr, std::uint8_t proto,
                                    const std::vector<uint8_t>& l4) {
    std::vector<uint8_t> frame;
    for (auto b : dst.b) frame.push_back(b);
    for (auto b : src.b) frame.push_back(b);

    if (srv_addr.is_v6()) {
        frame.push_back(0x86);
        frame.push_back(0xDD); // IPv6
        std::vector<uint8_t> ip(40, 0);
        ip[0] = 0x60; // version 6, traffic class and flow label zero
        const auto v6len = static_cast<std::uint16_t>(l4.size());
        ip[4] = static_cast<std::uint8_t>(v6len >> 8);   // payload length (bytes 4-5)
        ip[5] = static_cast<std::uint8_t>(v6len & 0xFF);
        ip[6] = proto;
        ip[7] = 64; // hop limit: let the physical path do PMTU discovery
        const auto sb = srv_addr.to_v6().to_bytes();
        std::copy(sb.begin(), sb.end(), ip.begin() + 8);
        const auto db = d_addr.to_v6().to_bytes();
        std::copy(db.begin(), db.end(), ip.begin() + 24);
        frame.insert(frame.end(), ip.begin(), ip.end());
    } else {
        frame.push_back(0x08);
        frame.push_back(0x00); // IPv4
        std::vector<uint8_t> ip(20, 0);
        ip[0] = 0x45; // v4, IHL 5
        static std::atomic<std::uint16_t> id_counter{1};
        const auto total_len = static_cast<std::uint16_t>(20 + l4.size());
        ip[2] = static_cast<std::uint8_t>(total_len >> 8);
        ip[3] = static_cast<std::uint8_t>(total_len & 0xFF);
        const auto id = id_counter.fetch_add(1) & 0xFFFF;
        ip[4] = static_cast<std::uint8_t>(id >> 8);
        ip[5] = static_cast<std::uint8_t>(id & 0xFF);
        ip[6] = 0x40; // DF: let the physical path do PMTU discovery
        ip[7] = 0x00;
        ip[8] = 64;   // TTL
        ip[9] = proto;
        const auto sb = srv_addr.to_v4().to_bytes();
        std::copy(sb.begin(), sb.end(), ip.begin() + 12);
        const auto db = d_addr.to_v4().to_bytes();
        std::copy(db.begin(), db.end(), ip.begin() + 16);
        const auto cs = checksum16(ip.data(), 20);
        ip[10] = static_cast<std::uint8_t>(cs >> 8);
        ip[11] = static_cast<std::uint8_t>(cs & 0xFF);
        frame.insert(frame.end(), ip.begin(), ip.end());
    }

    frame.insert(frame.end(), l4.begin(), l4.end());
    return frame;
}

std::vector<uint8_t> build_arp_frame(std::uint16_t opcode, const Mac& sender_mac,
                                     std::uint32_t sender_ip_nbo, const Mac& target_mac,
                                     std::uint32_t target_ip_nbo) {
    std::vector<uint8_t> frame;
    for (auto b : target_mac.b) frame.push_back(b); // Ethernet dst = requester
    for (auto b : kEgressMac.b) frame.push_back(b);  // Ethernet src = us
    frame.push_back(0x08);
    frame.push_back(0x06); // ARP

    auto put16 = [&frame](std::uint16_t v) { put_nbo16(frame, v); };
    put16(1);      // hardware: Ethernet
    put16(0x0800); // protocol: IPv4
    frame.push_back(6); // hlen
    frame.push_back(4); // plen
    put16(opcode);
    for (auto b : sender_mac.b) frame.push_back(b);
    put_nbo32(frame, sender_ip_nbo);
    for (auto b : target_mac.b) frame.push_back(b);
    put_nbo32(frame, target_ip_nbo);
    return frame;
}

} // namespace

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

bool seq_lt(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b) < 0; }
bool seq_eq(std::uint32_t a, std::uint32_t b) { return a == b; }

std::uint16_t checksum16(const std::uint8_t* data, std::size_t len) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        sum += static_cast<std::uint32_t>((static_cast<std::uint16_t>(data[i]) << 8) | data[i + 1]);
    }
    if (len & 1u) sum += static_cast<std::uint32_t>(data[len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum & 0xFFFFu);
}

// Pseudo-header per RFC 791 (v4: src+dst+reserved+proto+len(16)) and
// RFC 2460 section 8.1 (v6: src+dst+len(32)+three zero bytes+next header).
std::uint16_t pseudo_checksum(const asio::ip::address& src, const asio::ip::address& dst,
                              std::uint8_t proto, const std::uint8_t* l4, std::size_t l4_len) {
    std::uint32_t sum = 0;
    auto add16 = [&sum](std::uint16_t v) { sum += v; };
    for (const auto& addr : {src, dst}) {
        const std::vector<uint8_t> b = addr.is_v4()
            ? std::vector<uint8_t>(addr.to_v4().to_bytes().begin(), addr.to_v4().to_bytes().end())
            : std::vector<uint8_t>(addr.to_v6().to_bytes().begin(), addr.to_v6().to_bytes().end());
        for (std::size_t i = 0; i + 1 < b.size(); i += 2)
            add16(static_cast<std::uint16_t>((b[i] << 8) | b[i + 1]));
        if (b.size() & 1u) add16(static_cast<std::uint16_t>(b.back() << 8));
    }
    sum += proto; // the reserved/zero bytes contribute nothing
    const auto len = static_cast<std::uint32_t>(l4_len);
    if (src.is_v6()) {
        add16(static_cast<std::uint16_t>(len >> 16));
    }
    add16(static_cast<std::uint16_t>(len & 0xFFFFu));
    for (std::size_t i = 0; i + 1 < l4_len; i += 2) {
        sum += static_cast<std::uint32_t>((static_cast<std::uint16_t>(l4[i]) << 8) | l4[i + 1]);
    }
    if (l4_len & 1u) sum += static_cast<std::uint32_t>(l4[l4_len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum & 0xFFFFu);
}

std::vector<uint8_t> build_tcp_frame(
    const Mac& dst, const Mac& src, const asio::ip::address& src_ip,
    const asio::ip::address& dst_ip, std::uint16_t sport, std::uint16_t dport,
    std::uint16_t flags, std::uint32_t seq, std::uint32_t ack, std::uint16_t window,
    const std::vector<uint8_t>& options, const std::uint8_t* payload, std::size_t payload_len) {
    std::vector<uint8_t> l4(20, 0);
    write_nbo16(l4.data(), sport);
    write_nbo16(l4.data() + 2, dport);
    write_nbo32(l4.data() + 4, seq);
    write_nbo32(l4.data() + 8, ack);
    // Data offset lives in the HIGH nibble (value in 32-bit words): 5 -> 0x50.
    l4[12] = 0x50; // fixed header only (options are appended after)
    l4[13] = static_cast<std::uint8_t>(flags & 0xFF);
    write_nbo16(l4.data() + 14, window);
    // checksum slot (16..17) stays zero for the computation below
    if (!options.empty()) {
        l4.insert(l4.end(), options.begin(), options.end());
        l4[12] = static_cast<std::uint8_t>((static_cast<unsigned>(20 + options.size()) / 4u) << 4);
    }
    if (payload_len && payload) l4.insert(l4.end(), payload, payload + payload_len);

    const auto cs = pseudo_checksum(src_ip, dst_ip, 6, l4.data(), l4.size());
    l4[16] = static_cast<std::uint8_t>(cs >> 8);
    l4[17] = static_cast<std::uint8_t>(cs & 0xFF);

    return build_ip_frame(dst, src, src_ip, dst_ip, 6, l4);
}

std::vector<uint8_t> build_udp_frame(
    const Mac& dst, const Mac& src, const asio::ip::address& src_ip,
    const asio::ip::address& dst_ip, std::uint16_t sport, std::uint16_t dport,
    const std::uint8_t* payload, std::size_t payload_len) {
    std::vector<uint8_t> l4(8, 0);
    write_nbo16(l4.data(), sport);
    write_nbo16(l4.data() + 2, dport);
    write_nbo16(l4.data() + 4, static_cast<std::uint16_t>(8 + payload_len));
    // checksum slot (6..7) stays zero for the computation below
    if (payload_len && payload) l4.insert(l4.end(), payload, payload + payload_len);

    const auto cs = pseudo_checksum(src_ip, dst_ip, 17, l4.data(), l4.size());
    l4[6] = static_cast<std::uint8_t>(cs >> 8);
    l4[7] = static_cast<std::uint8_t>(cs & 0xFF);

    return build_ip_frame(dst, src, src_ip, dst_ip, 17, l4);
}

std::vector<uint8_t> build_arp_reply(const Mac& client_mac, std::uint32_t claimed_ip_nbo,
                                     const Mac& egress_mac, std::uint32_t client_ip_nbo) {
    (void)egress_mac; // kEgressMac is fixed by design (see build_arp_frame)
    return build_arp_frame(2 /*reply*/, kEgressMac, claimed_ip_nbo, client_mac, client_ip_nbo);
}

std::size_t EgressForwarder::FlowKeyHash::operator()(const FlowKey& k) const noexcept {
    auto h = std::hash<asio::ip::address>{}(k.client_addr);
    h ^= std::hash<asio::ip::address>{}(k.server_addr) + 0x9e3779b97f4a7c15ull + (h << 6)
           + (h >> 2);
    auto mix = [&h](std::uint64_t v) {
        h ^= static_cast<std::uint64_t>(v);
        h *= 1099511628211ull;
    };
    mix(k.client_port);
    mix(k.server_port);
    mix(k.proto);
    return static_cast<std::size_t>(h);
}

std::size_t EgressForwarder::FragKeyHash::operator()(const FragKey& k) const noexcept {
    auto h = std::hash<asio::ip::address>{}(k.src);
    h ^= std::hash<asio::ip::address>{}(k.dst) + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
    h ^= static_cast<std::uint64_t>(k.id);
    h *= 1099511628211ull;
    return static_cast<std::size_t>(h);
}

// ---------------------------------------------------------------------------
// EgressForwarder
// ---------------------------------------------------------------------------

EgressForwarder::EgressForwarder(asio::io_context& io) : io_(io), sweeper_(io) {
    start_sweeper();
}

EgressForwarder::~EgressForwarder() = default;

std::size_t EgressForwarder::flow_count() const { return tcp_flows_.size() + udp_flows_.size(); }

bool EgressForwarder::emit(const std::vector<uint8_t>& frame, const std::vector<uint8_t>& peer) const {
    if (!sender_) return false;
    try {
        return sender_(frame, peer);
    } catch (const std::exception& error) {
        pqvpn::logging::Logger::warn("egress: tunnel send failed: {}", error.what());
        return false;
    }
}

// Transport dispatch shared by the IPv4 and IPv6 paths (and by fragment
// reassembly): `l4` is the complete transport segment of a whole datagram.
bool EgressForwarder::dispatch_l4(const Mac& client_mac, const asio::ip::address& c_addr,
                                  const asio::ip::address& srv_addr, std::uint8_t proto,
                                  const std::uint8_t* l4, std::size_t l4_len,
                                  const std::vector<uint8_t>& owner_peer) {
    if (proto == 1 && c_addr.is_v4()) {
        if (l4_len < 8) return kConsumed; // truncated ICMP header: ours to drop
        handle_icmp(client_mac, c_addr.to_v4().to_uint(), srv_addr.to_v4().to_uint(), l4, l4_len,
                    owner_peer);
        return kConsumed;
    }
    if (proto == 58) {
        // ICMPv6: answering or forwarding it needs raw sockets / kernel
        // forwarding, which normal permissions do not grant. Consume instead
        // of leaking onto an unattached adapter.
        pqvpn::logging::Logger::debug("egress: consuming unsupported ICMPv6");
        return kConsumed;
    }
    if (proto == 6) {
        if (l4_len < 20) return kConsumed;
        handle_tcp(client_mac, c_addr, srv_addr, ntohs_u(l4), ntohs_u(l4 + 2), l4, l4_len,
                   owner_peer);
        return kConsumed;
    }
    if (proto == 17) {
        if (l4_len < 8) return kConsumed;
        const auto cp = ntohs_u(l4);
        const auto sp = ntohs_u(l4 + 2);
        const auto udp_len = ntohs_u(l4 + 4);
        if (udp_len < 8 || static_cast<std::size_t>(udp_len) > l4_len) return kConsumed;
        handle_udp(client_mac, c_addr, srv_addr, cp, sp, l4 + 8,
                   static_cast<std::size_t>(udp_len) - 8u, owner_peer);
        return kConsumed;
    }
    pqvpn::logging::Logger::debug("egress: not forwarding proto {}", proto);
    return false; // other protocols fall through to the legacy adapter write
}

bool EgressForwarder::handle_fragment(const Mac& client_mac, const std::uint8_t* ip,
                                      std::uint16_t total_len, std::size_t frame_ip_len,
                                      const std::vector<uint8_t>& owner_peer) {
    if (total_len < 20 || static_cast<std::size_t>(total_len) > frame_ip_len) return kConsumed;
    const auto ihl = static_cast<std::size_t>(ip[0] & 0x0F) * 4u;
    if (ihl < 20 || total_len < ihl) return kConsumed; // options are not reassembled
    const auto frag_field = ntohs_u(ip + 6);
    const auto offset_bytes = static_cast<std::size_t>(frag_field & 0x1FFF) * 8u;
    const bool more = (frag_field & 0x2000) != 0;

    const asio::ip::address src(asio::ip::address_v4(ntohl_u(ip + 12)));
    const asio::ip::address dst(asio::ip::address_v4(ntohl_u(ip + 16)));
    FragKey key{src, dst, ntohs_u(ip + 4)};

    const auto now = now_seconds();
    // Keep the table bounded: expire stale entries before refusing new work.
    if (fragments_.size() >= kMaxFragmentEntries) {
        for (auto it = fragments_.begin(); it != fragments_.end();) {
            if (now > it->second.deadline) it = fragments_.erase(it);
            else ++it;
        }
        if (fragments_.size() >= kMaxFragmentEntries) {
            pqvpn::logging::Logger::warn("egress: reassembly table full; dropping fragment");
            return kConsumed;
        }
    }

    auto it = fragments_.find(key);
    if (it == fragments_.end()) {
        FragEntry e;
        e.src = src;
        e.dst = dst;
        e.proto = ip[9];
        e.deadline = now + fragment_timeout_;
        it = fragments_.emplace(std::move(key), std::move(e)).first;
    } else if (now > it->second.deadline) {
        // The datagram is stale: drop this piece and let the sender time out.
        fragments_.erase(it);
        pqvpn::logging::Logger::debug("egress: dropping fragment of an expired reassembly");
        return kConsumed;
    }

    auto& e = it->second;
    const std::uint8_t* payload = ip + ihl;
    const std::size_t plen = static_cast<std::size_t>(total_len) - ihl;
    if (e.bytes + plen > kMaxReassemblyBytes) {
        fragments_.erase(it);
        pqvpn::logging::Logger::warn("egress: reassembly exceeds {} bytes; dropping",
                                     kMaxReassemblyBytes);
        return kConsumed;
    }
    const bool inserted =
        e.pieces.emplace(offset_bytes, std::vector<uint8_t>(payload, payload + plen)).second;
    if (inserted) e.bytes += plen;
    if (!more) e.total_len = std::max(e.total_len, offset_bytes + plen);

    // Complete only when the last fragment arrived and every byte from 0 is
    // covered contiguously.
    if (e.total_len == 0) return kConsumed; // still waiting for MF=0
    std::vector<uint8_t> l4;
    l4.reserve(e.total_len);
    auto pit = e.pieces.begin();
    std::size_t next = 0;
    while (pit != e.pieces.end() && pit->first == next) {
        l4.insert(l4.end(), pit->second.begin(), pit->second.end());
        next += pit->second.size();
        pit = e.pieces.erase(pit);
    }
    if (next < e.total_len) return kConsumed; // gap: wait for the missing piece(s)

    // Copy out before erasing: `e` references the map element that is about
    // to be destroyed.
    const asio::ip::address src_addr = e.src;
    const asio::ip::address dst_addr = e.dst;
    const auto proto = e.proto;
    fragments_.erase(it);
    pqvpn::logging::Logger::debug("egress: reassembled {} bytes of a fragmented datagram",
                                  next);
    return dispatch_l4(client_mac, src_addr, dst_addr, proto, l4.data(), l4.size(), owner_peer);
}

bool EgressForwarder::handle_frame(const std::uint8_t* d, std::size_t len,
                                   const std::vector<uint8_t>& owner_peer) {
    if (!sender_ || len < 14) return false;
    const auto ethertype = ntohs_u(d + 12);
    if (ethertype == 0x0806) return handle_arp(d, len, owner_peer);

    // The requester's MAC is the frame SOURCE (bytes 6..11), not the
    // destination: return frames must be addressed to it.
    const Mac client_mac{std::array<uint8_t, 6>{d[6], d[7], d[8], d[9], d[10], d[11]}};

    if (ethertype == 0x0800) {
        // IPv4 header.
        if ((d[14] >> 4) != 4) return false;
        const auto ihl = static_cast<std::size_t>(d[14] & 0x0F) * 4u;
        if (ihl < 20 || len < 14 + ihl) return false;
        const auto total_len = ntohs_u(d + 16);
        if (total_len < ihl || static_cast<std::size_t>(total_len) > len - 14) {
            pqvpn::logging::Logger::warn("egress: IPv4 total length {} out of bounds", total_len);
            return kConsumed; // malformed but ours to drop, not the adapter's
        }
        const std::uint8_t* ip = d + 14;
        const auto frag = ntohs_u(ip + 6);
        if (frag & 0x3FFF || (frag & 0x2000)) {
            // Fragmented datagram: reassemble before dispatching.
            return handle_fragment(client_mac, ip, total_len, len - 14, owner_peer);
        }
        const auto proto = ip[9];
        const std::uint8_t* l4 = ip + ihl;
        const std::size_t l4_len = static_cast<std::size_t>(total_len) - ihl;
        const auto c_addr = asio::ip::address_v4(ntohl_u(ip + 12));
        const auto srv_addr = asio::ip::address_v4(ntohl_u(ip + 16));
        return dispatch_l4(client_mac, c_addr, srv_addr, proto, l4, l4_len, owner_peer);
    }

    if (ethertype == 0x86DD) {
        // IPv6 header: no checksum field, no fragmentation offset; the payload
        // length covers the transport segment (jumbograms are out of scope).
        if ((d[14] >> 4) != 6 || len < 14 + 40) return false;
        const std::uint8_t* ip = d + 14;
        const auto payload_len = ntohs_u(ip + 4);
        if (payload_len == 0 || static_cast<std::size_t>(payload_len) > len - 54) {
            pqvpn::logging::Logger::warn("egress: IPv6 payload length {} out of bounds",
                                         payload_len);
            return kConsumed; // malformed but ours to drop, not the adapter's
        }
        const auto proto = ip[6];
        const std::uint8_t* l4 = ip + 40;
        auto from_bytes_v6 = [](const std::uint8_t* p) {
            asio::ip::address_v6::bytes_type b{};
            std::copy_n(p, 16, b.begin());
            return asio::ip::address(asio::ip::address_v6(b));
        };
        const auto c_addr = from_bytes_v6(ip + 8);
        const auto srv_addr = from_bytes_v6(ip + 24);
        return dispatch_l4(client_mac, c_addr, srv_addr, proto, l4,
                           static_cast<std::size_t>(payload_len), owner_peer);
    }

    pqvpn::logging::Logger::debug("egress: not consuming ethertype 0x{:04X}", ethertype);
    return false;
}

bool EgressForwarder::handle_arp(const std::uint8_t* d, std::size_t len,
                                 const std::vector<uint8_t>& owner_peer) {
    if (len < 14 + 28) return false;
    const std::uint8_t* a = d + 14;
    if (ntohs_u(a) != 1 || ntohs_u(a + 2) != 0x0800 || a[4] != 6 || a[5] != 4) return false;
    const auto opcode = ntohs_u(a + 6);
    if (opcode != 1) { // replies and anything else: nothing to do
        return kConsumed;
    }
    const Mac client_mac{std::array<uint8_t, 6>{d[6], d[7], d[8], d[9], d[10], d[11]}};
    const auto client_ip_nbo = ntohl_u(a + 14); // sender IP
    const auto claimed_ip_nbo = ntohl_u(a + 24); // target IP being resolved
    pqvpn::logging::Logger::info("egress: answering ARP for {} (client {})",
                                 asio::ip::address_v4(claimed_ip_nbo).to_string(),
                                 asio::ip::address_v4(client_ip_nbo).to_string());
    emit(build_arp_reply(client_mac, claimed_ip_nbo, kEgressMac, client_ip_nbo), owner_peer);
    return kConsumed;
}

void EgressForwarder::handle_icmp(const Mac& client_mac, std::uint32_t c_nbo, std::uint32_t s_nbo,
                                  const std::uint8_t* l4, std::size_t l4_len,
                                  const std::vector<uint8_t>& owner_peer) {
    const auto type = l4[0];
    const auto code = l4[1];
    if (type == 8 && code == 0 && s_nbo == gateway_ip_nbo_) {
        // Echo request to the virtual gateway: answer it ourselves. The reply
        // mirrors id/seq/payload and swaps the endpoints; only the type byte
        // and checksum change.
        std::vector<uint8_t> msg(l4, l4 + l4_len);
        msg[0] = 0; // echo reply
        // The checksum field must be zero while the new value is computed
        // (RFC 792 / RFC 1071): the copied request still carries its own,
        // valid checksum, and folding it in would corrupt the result.
        msg[2] = 0;
        msg[3] = 0;
        const auto cs = checksum16(msg.data(), msg.size());
        msg[2] = static_cast<std::uint8_t>(cs >> 8);
        msg[3] = static_cast<std::uint8_t>(cs & 0xFF);
        pqvpn::logging::Logger::info("egress: answering ICMP echo from {} ({} bytes)",
                                     asio::ip::address_v4(c_nbo).to_string(), l4_len - 8u);
        const asio::ip::address_v4 gw_v4{gateway_ip_nbo_};
        const asio::ip::address_v4 client_v4{c_nbo};
        emit(build_ip_frame(client_mac, kEgressMac, asio::ip::address(gw_v4),
                            asio::ip::address(client_v4), 1, msg),
             owner_peer);
        return;
    }
    // Everything else (echo to a foreign destination, errors, queries) needs
    // raw sockets or kernel forwarding, which normal permissions do not grant:
    // consume it here instead of leaking it onto an unattached adapter.
    pqvpn::logging::Logger::debug("egress: consuming unsupported ICMP type {} code {}", type,
                                  code);
}

// ---------------------------------------------------------------------------
// TCP flows
// ---------------------------------------------------------------------------

void EgressForwarder::handle_tcp(const Mac& client_mac, const asio::ip::address& c_addr,
                                 const asio::ip::address& srv_addr, std::uint16_t cp,
                                 std::uint16_t sp, const std::uint8_t* l4, std::size_t l4_len,
                                 const std::vector<uint8_t>& owner_peer) {
    const auto seq = ntohl_u(l4 + 4); // sport(2)+dport(2) precede il sequence number
    const auto ack = ntohl_u(l4 + 8);
    const auto dataoff = static_cast<std::size_t>(l4[12] >> 4) * 4u;
    const auto flags = l4[13] & 0xFF; // single flag byte (window follows)
    if (dataoff < 20 || l4_len < dataoff) {
        pqvpn::logging::Logger::warn("egress: malformed TCP header dataoff={} l4len={}",
                                     dataoff, l4_len);
        return;
    }
    const std::uint8_t* payload = l4 + dataoff;
    const std::size_t plen = l4_len - dataoff;

    FlowKey key{c_addr, srv_addr, cp, sp, 6};
    auto it = tcp_flows_.find(key);
    if (it == tcp_flows_.end()) {
        if (!(flags & kFlagSyn)) {
            pqvpn::logging::Logger::warn("egress: TCP frame without SYN; refusing to join mid-stream");
            return; // fail closed: no flow is created
        }
        if (flow_count() >= kMaxFlows) {
            pqvpn::logging::Logger::warn("egress: flow limit reached; refusing new TCP flow");
            emit(build_tcp_frame(client_mac, kEgressMac, srv_addr, c_addr, sp, cp,
                                 kFlagRst | kFlagAck, 0, seq + 1, 0, {}),
                 owner_peer);
            return;
        }

        auto f = std::make_shared<TcpFlow>();
        f->owner_peer = owner_peer;
        f->client_mac = client_mac;
        f->client_addr = c_addr;
        f->server_addr = srv_addr;
        f->client_port = cp;
        f->server_port = sp;
        f->isn_c = seq;
        f->recv_next = seq + 1;
        f->isn_s = random_isn();
        f->send_next = f->isn_s + 1;
        // Parse the client's MSS option (kind 2); default to a safe 1460.
        for (std::size_t i = 20; i + 3 < dataoff;) {
            const auto kind = l4[i];
            const auto olen = l4[i + 1];
            if (olen < 2) break;
            if (kind == 1) { i += 1; continue; } // NOP
            if (kind == 2 && olen == 4) f->mss_c = ntohs_u(l4 + i + 2);
            i += olen;
        }
        f->mss_c = std::max<std::uint16_t>(f->mss_c, 536);
        f->mss_c = std::min(f->mss_c, static_cast<std::uint16_t>(1460));
        f->sock = std::make_shared<asio::ip::tcp::socket>(io_);
        asio::error_code open_ec;
        // The socket family follows the flow's IP family (v4 or v6).
        f->sock->open(srv_addr.is_v6() ? asio::ip::tcp::v6() : asio::ip::tcp::v4(), open_ec);
        if (open_ec) {
            // Flow not inserted yet: just bail out.
            pqvpn::logging::Logger::warn("egress: cannot open TCP socket: {}", open_ec.message());
            return;
        }
        f->target = asio::ip::tcp::endpoint(srv_addr, sp);
        f->last_activity = now_seconds();
        tcp_flows_.emplace(key, f);
        pqvpn::logging::Logger::info(
            "egress: new TCP flow {}:{} -> {}:{} (client ISN {:X}, MSS {})", c_addr.to_string(),
            cp, srv_addr.to_string(), sp, seq, f->mss_c);
        start_connect(f);
        return; // SYN-ACK is sent once the upstream connect completes
    }

    auto f = it->second;
    if (f->closed) return;
    f->last_activity = now_seconds();

    if (flags & kFlagAck) {
        f->c_ack = ack;
        f->have_c_ack = true;
    }

    if (flags & kFlagRst) {
        pqvpn::logging::Logger::info("egress: client RST; closing TCP flow");
        abort_flow(f, false); // the client already aborted; nothing to send back
        return;
    }

    if ((flags & kFlagSyn) && !f->syn_ack_sent) {
        // Retransmitted SYN while we are still dialing upstream: wait.
        return;
    }

    if (flags & kFlagFin) {
        f->c_fin_seen = true;
        if (!f->send_shutdown_done && f->sock) {
            asio::error_code ec;
            f->sock->shutdown(asio::socket_base::shutdown_type::shutdown_send, ec);
            f->send_shutdown_done = true;
        }
        if (f->fin_sent_c) abort_flow(f, false); // both directions done: release
    }

    accept_client_data(f, seq, payload, plen);
    if (f->syn_ack_sent && !f->closed) {
        send_ack_to_client(f); // cumulative ACK (also answers pure retransmits)
        deliver_server_bytes(f); // an ACK may have lifted backpressure
    }
}

void EgressForwarder::start_connect(std::shared_ptr<TcpFlow> f) {
    auto w = std::weak_ptr<TcpFlow>(f);
    asio::error_code ec;
    f->sock->cancel(ec); // no pending ops yet; defensive
    f->sock->async_connect(f->target, [this, w](const asio::error_code& connect_ec) {
        on_connect_done(w, connect_ec);
    });
}

void EgressForwarder::on_connect_done(std::weak_ptr<TcpFlow> w, const asio::error_code& ec) {
    auto f = w.lock();
    if (!f || f->closed) return;
    if (ec) {
        pqvpn::logging::Logger::warn("egress: connect to {}:{} failed: {}",
                                     f->target.address().to_string(), f->target.port(), ec.message());
        // Tell the client its connection was refused.
        emit(build_tcp_frame(f->client_mac, kEgressMac, f->server_addr, f->client_addr,
                             f->server_port, f->client_port, kFlagRst | kFlagAck, f->isn_s,
                             f->isn_c + 1, 0, {}),
             f->owner_peer);
        abort_flow(f, false);
        return;
    }
    f->syn_ack_sent = true;
    pqvpn::logging::Logger::info(
        "egress: TCP flow established {}:{} -> {}:{} (client ISN {:X}, egress ISN {:X})",
        f->client_addr.to_string(), f->client_port, f->server_addr.to_string(), f->server_port,
        f->isn_c, f->isn_s);
    // Synthesized SYN-ACK: our own ISN for the S->C direction, acknowledging
    // the client's SYN. No window-scale option is advertised, so the client
    // reads our windows unscaled.
    std::vector<uint8_t> options = {2, 4}; // MSS option
    put_nbo16(options, f->mss_c);
    emit(build_tcp_frame(f->client_mac, kEgressMac, f->server_addr, f->client_addr,
                         f->server_port, f->client_port, kFlagSyn | kFlagAck, f->isn_s,
                         f->isn_c + 1, 65535, options),
         f->owner_peer);
    start_server_read(w);
    try_flush(w); // drain anything buffered while we were dialing
}

void EgressForwarder::accept_client_data(std::shared_ptr<TcpFlow> f, std::uint32_t seq,
                                         const std::uint8_t* payload, std::size_t plen) {
    if (plen == 0 || f->closed) return;
    if (seq_eq(seq, f->recv_next)) {
        append_pending(f, payload, plen);
        // In-order bytes are accepted now: advance the expected sequence so
        // subsequent ACKs and OOO bookkeeping reflect what we have seen.
        f->recv_next += static_cast<std::uint32_t>(plen);
        drain_ooo(f);
        try_flush(std::weak_ptr<TcpFlow>(f));
    } else if (seq_lt(seq, f->recv_next)) {
        // Duplicate / retransmit of already-accepted bytes: the cumulative ACK
        // sent by the caller is enough.
    } else {
        if (f->ooo.size() >= kMaxOooEntries) {
            pqvpn::logging::Logger::warn("egress: out-of-order buffer full; resetting flow");
            abort_flow(f, true);
            return;
        }
        f->ooo[seq] = std::vector<uint8_t>(payload, payload + plen);
        drain_ooo(f);
        try_flush(std::weak_ptr<TcpFlow>(f));
    }
}

void EgressForwarder::drain_ooo(std::shared_ptr<TcpFlow> f) {
    while (true) {
        auto it = f->ooo.find(f->recv_next);
        if (it == f->ooo.end()) break;
        append_pending(f, it->second.data(), it->second.size());
        f->recv_next += static_cast<std::uint32_t>(it->second.size());
        f->ooo.erase(it);
    }
}

void EgressForwarder::append_pending(std::shared_ptr<TcpFlow> f, const std::uint8_t* p,
                                     std::size_t n) {
    if (f->pending.size() + n > kMaxPendingBytes) {
        pqvpn::logging::Logger::warn("egress: client upload queue overflow; resetting flow");
        abort_flow(f, true);
        return;
    }
    f->pending.insert(f->pending.end(), p, p + n);
}

void EgressForwarder::try_flush(std::weak_ptr<TcpFlow> w) {
    auto f = w.lock();
    if (!f || f->closed || !f->syn_ack_sent || f->flushing || f->pending.empty()) return;
    f->flushing = true;
    // The write must own the bytes: `data` is a local that would dangle once
    // this function returns (the handler does not capture it by value).
    auto data = std::make_shared<std::vector<uint8_t>>();
    data->swap(f->pending);
    asio::async_write(
        *f->sock, asio::buffer(*data),
        [this, w, data](const asio::error_code& ec, std::size_t /*written*/) {
            auto ff = w.lock();
            if (!ff || ff->closed) return;
            ff->flushing = false;
            if (ec) {
                pqvpn::logging::Logger::warn("egress: upstream write failed: {}", ec.message());
                abort_flow(ff, true);
                return;
            }
            // Bytes are safely in the kernel: acknowledge them to the client.
            send_ack_to_client(ff);
            try_flush(w); // continue with anything that arrived meanwhile
        });
}

void EgressForwarder::start_server_read(std::weak_ptr<TcpFlow> w) {
    auto f = w.lock();
    if (!f || f->closed || !f->sock) return;
    // Same buffer-lifetime rule as start_udp_recv: the handler must own the
    // storage (shared_ptr), not a moved-from local.
    auto buf = std::make_shared<std::vector<uint8_t>>(65536);
    f->sock->async_read_some(
        asio::buffer(*buf), [this, w, buf](const asio::error_code& ec,
                                           std::size_t n) {
            auto ff = w.lock();
            if (!ff || ff->closed) return;
            if (ec == asio::error::eof) {
                ff->s_eof = true;
                // Server closed: send FIN to the client and keep the flow for
                // any remaining upload until it finishes or times out.
                if (!ff->fin_sent_c) {
                    emit(build_tcp_frame(ff->client_mac, kEgressMac, ff->server_addr,
                                         ff->client_addr, ff->server_port, ff->client_port,
                                         kFlagFin | kFlagAck, ff->send_next, ff->recv_next, 0, {}),
                         ff->owner_peer);
                    ff->fin_sent_c = true;
                    ff->send_next += 1; // FIN consumes one sequence number
                }
                if (ff->c_fin_seen) abort_flow(ff, false); // both directions done
                return;
            }
            if (ec) {
                pqvpn::logging::Logger::warn("egress: upstream read failed: {}", ec.message());
                abort_flow(ff, true);
                return;
            }
            ff->last_activity = now_seconds();
            if (ff->sbuf.size() - ff->sbuf_off + n > kMaxServerBuffer) {
                pqvpn::logging::Logger::warn("egress: server buffer overflow; resetting flow");
                abort_flow(ff, true);
                return;
            }
            ff->sbuf.insert(ff->sbuf.end(), buf->begin(), buf->begin() + static_cast<long>(n));
            deliver_server_bytes(ff);
            start_server_read(w); // keep reading
        });
}

void EgressForwarder::deliver_server_bytes(std::shared_ptr<TcpFlow> f) {
    if (!f || f->closed) return;
    const auto max_seg = std::min<std::size_t>(f->mss_c, 1460);
    while (f->sbuf_off < f->sbuf.size() && !f->closed) {
        // Backpressure: do not run further than the client's acknowledged window.
        if (f->have_c_ack && seq_lt(f->c_ack, f->send_next) &&
            static_cast<std::int32_t>(f->send_next - f->c_ack) > kMaxInFlightBytes) {
            break; // resume on the next ACK from the client
        }
        const auto chunk = std::min(max_seg, f->sbuf.size() - f->sbuf_off);
        const bool ok = emit(build_tcp_frame(
                             f->client_mac, kEgressMac, f->server_addr, f->client_addr,
                             f->server_port, f->client_port, kFlagAck, f->send_next, f->recv_next,
                             65535, {}, f->sbuf.data() + f->sbuf_off, chunk),
                         f->owner_peer);
        if (!ok) {
            pqvpn::logging::Logger::warn("egress: tunnel send failed; dropping flow");
            abort_flow(f, false);
            return;
        }
        f->send_next += static_cast<std::uint32_t>(chunk);
        f->sbuf_off += chunk;
    }
    if (f->sbuf_off >= f->sbuf.size()) {
        f->sbuf.clear();
        f->sbuf_off = 0;
    }
}

void EgressForwarder::send_ack_to_client(const std::shared_ptr<TcpFlow>& f,
                                         std::uint16_t extra_flags) {
    if (!f || f->closed) return;
    emit(build_tcp_frame(f->client_mac, kEgressMac, f->server_addr, f->client_addr,
                         f->server_port, f->client_port, kFlagAck | extra_flags, f->send_next,
                         f->recv_next, 65535, {}),
         f->owner_peer);
}

void EgressForwarder::abort_flow(const std::shared_ptr<TcpFlow>& f, bool reset_client) {
    if (!f || f->closed) return;
    f->closed = true;
    if (reset_client) {
        emit(build_tcp_frame(f->client_mac, kEgressMac, f->server_addr, f->client_addr,
                             f->server_port, f->client_port, kFlagRst | kFlagAck, f->send_next,
                             f->recv_next, 0, {}),
             f->owner_peer);
    }
    if (f->sock) {
        asio::error_code ec;
        f->sock->close(ec); // cancels pending ops; handlers see operation_aborted
    }
    for (auto it = tcp_flows_.begin(); it != tcp_flows_.end(); ++it) {
        if (it->second == f) {
            tcp_flows_.erase(it);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// UDP flows
// ---------------------------------------------------------------------------

void EgressForwarder::handle_udp(const Mac& client_mac, const asio::ip::address& c_addr,
                                 const asio::ip::address& srv_addr, std::uint16_t cp,
                                 std::uint16_t sp, const std::uint8_t* payload,
                                 std::size_t plen, const std::vector<uint8_t>& owner_peer) {
    if (plen == 0) return;
    FlowKey key{c_addr, srv_addr, cp, sp, 17};
    auto it = udp_flows_.find(key);
    if (it == udp_flows_.end()) {
        if (flow_count() >= kMaxFlows) {
            pqvpn::logging::Logger::warn("egress: flow limit reached; dropping UDP datagram");
            return;
        }
        auto f = std::make_shared<UdpFlow>();
        f->owner_peer = owner_peer;
        f->client_mac = client_mac;
        f->client_addr = c_addr;
        f->server_addr = srv_addr;
        f->client_port = cp;
        f->server_port = sp;
        f->sock = std::make_shared<asio::ip::udp::socket>(io_);
        asio::error_code open_ec;
        // The socket family follows the flow's IP family (v4 or v6).
        if (srv_addr.is_v6()) {
            f->sock->open(asio::ip::udp::v6(), open_ec);
        } else {
            f->sock->open(asio::ip::udp::v4(), open_ec);
        }
        if (open_ec) {
            // Flow not inserted yet: just bail out.
            pqvpn::logging::Logger::warn("egress: cannot open UDP socket: {}", open_ec.message());
            return;
        }
        if (srv_addr.is_v6()) {
            f->sock->bind(asio::ip::udp::endpoint(asio::ip::address_v6::any(), 0), open_ec);
        } else {
            f->sock->bind(asio::ip::udp::endpoint(asio::ip::address_v4::any(), 0), open_ec);
        }
        f->target = asio::ip::udp::endpoint(srv_addr, sp);
        f->last_activity = now_seconds();
        udp_flows_.emplace(key, f);
        pqvpn::logging::Logger::info("egress: new UDP flow {}:{} -> {}:{} ({} bytes)",
                                     c_addr.to_string(), cp, srv_addr.to_string(), sp, plen);
        start_udp_recv(std::weak_ptr<UdpFlow>(f));
    } else {
        it->second->last_activity = now_seconds();
    }

    auto flow = udp_flows_.find(key)->second;
    if (flow->closed) return;
    asio::error_code ec;
    flow->sock->send_to(asio::buffer(payload, plen), flow->target, 0, ec);
    if (ec) {
        pqvpn::logging::Logger::warn("egress: UDP send failed: {}", ec.message());
        abort_udp(flow);
    }
}

void EgressForwarder::start_udp_recv(std::weak_ptr<UdpFlow> w) {
    auto f = w.lock();
    if (!f || f->closed || !f->sock) return;
    // The receive buffer must outlive the operation. A shared_ptr is used
    // (rather than a local moved into the handler) because argument evaluation
    // order is unspecified: if the handler were constructed before
    // asio::buffer() snapshots the vector, the move would leave a zero-length
    // receive buffer and Windows silently discards the datagram (n=0).
    auto buf = std::make_shared<std::vector<uint8_t>>(65536);
    asio::ip::udp::endpoint from;
    f->sock->async_receive_from(
        asio::buffer(*buf), from, [this, w, buf](const asio::error_code& ec,
                                                 std::size_t n) {
            auto ff = w.lock();
            if (!ff || ff->closed) return;
            if (ec == asio::error::eof) {
                abort_udp(ff); // peer closed the datagram association
                return;
            }
            if (ec) {
                pqvpn::logging::Logger::warn("egress: UDP recv failed: {}", ec.message());
                abort_udp(ff);
                return;
            }
            ff->last_activity = now_seconds();
            const bool ok = emit(build_udp_frame(ff->client_mac, kEgressMac, ff->server_addr,
                                                 ff->client_addr, ff->server_port,
                                                 ff->client_port, buf->data(), n),
                                 ff->owner_peer);
            if (!ok) {
                abort_udp(ff);
                return;
            }
            start_udp_recv(w); // keep listening for further replies
        });
}

void EgressForwarder::abort_udp(const std::shared_ptr<UdpFlow>& f) {
    if (!f || f->closed) return;
    f->closed = true;
    if (f->sock) {
        asio::error_code ec;
        f->sock->close(ec);
    }
    for (auto it = udp_flows_.begin(); it != udp_flows_.end(); ++it) {
        if (it->second == f) {
            udp_flows_.erase(it);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Sweeper (idle flow reaper)
// ---------------------------------------------------------------------------

void EgressForwarder::start_sweeper() { arm_sweeper(); }

void EgressForwarder::arm_sweeper() {
    sweeper_.expires_after(sweep_interval_);
    sweeper_.async_wait([this](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) return; // shutting down
        sweep_once();
        arm_sweeper();
    });
}

void EgressForwarder::sweep_once() {
    const auto now = now_seconds();
    std::vector<std::shared_ptr<TcpFlow>> dead_tcp;
    for (const auto& [key, f] : tcp_flows_) {
        if (!f->closed && now - f->last_activity > kTcpIdleTimeoutSeconds) dead_tcp.push_back(f);
    }
    for (auto& f : dead_tcp) {
        pqvpn::logging::Logger::info("egress: reaping idle TCP flow");
        abort_flow(f, true);
    }
    std::vector<std::shared_ptr<UdpFlow>> dead_udp;
    for (const auto& [key, f] : udp_flows_) {
        if (!f->closed && now - f->last_activity > kUdpIdleTimeoutSeconds) dead_udp.push_back(f);
    }
    for (auto& f : dead_udp) abort_udp(f);

    // Stale fragment reassemblies: memory must not grow without bound.
    for (auto it = fragments_.begin(); it != fragments_.end();) {
        if (now > it->second.deadline) {
            pqvpn::logging::Logger::debug("egress: expiring partial fragment reassembly");
            it = fragments_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace pqvpn::egress
