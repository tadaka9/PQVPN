#ifndef PQVPN_EGRESS_FORWARDER_HPP
#define PQVPN_EGRESS_FORWARDER_HPP

#include <asio.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

namespace pqvpn::egress {

// Delivers one fully built Ethernet frame back through the tunnel to a
// SPECIFIC client: `peer_id` is the identity of the tunnel peer that owns
// the flow (bound when its first frame was seen). Returns false when no live
// session can carry it (the frame is dropped).
using FrameSender =
    std::function<bool(const std::vector<uint8_t>&, const std::vector<uint8_t>&)>;

struct Mac {
    std::array<std::uint8_t, 6> b{};
};

// One bridged TCP flow: a synthesized client-side handshake plus two real
// byte streams (client->server extracted in order; server->client segmented
// in the egress sequence space). See egress_forwarder.cpp for the state
// machine.
struct TcpFlow {
    std::shared_ptr<asio::ip::tcp::socket> sock;
    asio::ip::tcp::endpoint target; // server side (host-order port)
    std::vector<uint8_t> owner_peer; // tunnel peer that owns this flow
    Mac client_mac{};
    asio::ip::address client_addr;  // v4 or v6, as seen in the frame
    asio::ip::address server_addr;  // v4 or v6
    std::uint16_t client_port = 0; // host order
    std::uint16_t server_port = 0; // host order

    bool syn_ack_sent = false;
    std::uint32_t isn_c = 0; // client ISN (host order)
    std::uint32_t isn_s = 0; // chosen ISN for the S->C direction
    std::uint16_t mss_c = 1460;

    // Client -> server byte extraction (client sequence space).
    std::uint32_t recv_next = 0; // next expected seq from the client
    std::vector<uint8_t> pending; // in-order bytes not yet written upstream
    std::map<std::uint32_t, std::vector<uint8_t>> ooo; // out-of-order segments
    bool flushing = false;
    bool c_fin_seen = false;
    bool send_shutdown_done = false;

    // Server -> client delivery (our own sequence space).
    std::uint32_t send_next = 0;
    std::vector<uint8_t> sbuf;
    std::size_t sbuf_off = 0;
    bool s_eof = false;
    bool fin_sent_c = false;

    // Client-side flow control for our S->C sends.
    bool have_c_ack = false;
    std::uint32_t c_ack = 0;

    bool closed = false; // terminal: no further processing
    double last_activity = 0.0;
};

// One bridged UDP flow: a per-flow socket relaying datagrams both ways.
struct UdpFlow {
    std::shared_ptr<asio::ip::udp::socket> sock;
    asio::ip::udp::endpoint target; // server side (host-order port)
    std::vector<uint8_t> owner_peer; // tunnel peer that owns this flow
    Mac client_mac{};
    asio::ip::address client_addr;  // v4 or v6, as seen in the frame
    asio::ip::address server_addr;  // v4 or v6
    std::uint16_t client_port = 0; // host order
    std::uint16_t server_port = 0; // host order
    bool closed = false;
    double last_activity = 0.0;
};

// RFC 1982 sequence-number comparisons (values in host order).
bool seq_lt(std::uint32_t a, std::uint32_t b);
bool seq_eq(std::uint32_t a, std::uint32_t b);

// One's-complement checksum over raw bytes (result NOT inverted... it IS the
// stored field value: caller writes it directly into the checksum slot).
std::uint16_t checksum16(const std::uint8_t* data, std::size_t len);

// TCP/UDP checksum including the IP pseudo-header (IPv4: src+dst+proto+len;
// IPv6: src+dst+len(32)+proto). `l4` is the complete transport header +
// payload with its checksum field zeroed; src/dst are the wire addresses.
std::uint16_t pseudo_checksum(const asio::ip::address& src, const asio::ip::address& dst,
                              std::uint8_t proto, const std::uint8_t* l4, std::size_t l4_len);

// Ethernet-II + IPv4 (DF, TTL 64) or IPv6 (hop limit 64) + TCP frame. The IP
// family follows src/dst (both must agree). `options` are the raw TCP option
// bytes that follow the fixed 20-byte header (e.g. MSS). sport/dport are host
// order; seq/ack/window host order.
std::vector<uint8_t> build_tcp_frame(
    const Mac& dst, const Mac& src, const asio::ip::address& src_ip,
    const asio::ip::address& dst_ip, std::uint16_t sport, std::uint16_t dport,
    std::uint16_t flags, std::uint32_t seq, std::uint32_t ack, std::uint16_t window,
    const std::vector<uint8_t>& options, const std::uint8_t* payload = nullptr,
    std::size_t payload_len = 0);

// Ethernet-II + IPv4 (DF, TTL 64) or IPv6 (hop limit 64) + UDP frame.
std::vector<uint8_t> build_udp_frame(
    const Mac& dst, const Mac& src, const asio::ip::address& src_ip,
    const asio::ip::address& dst_ip, std::uint16_t sport, std::uint16_t dport,
    const std::uint8_t* payload = nullptr, std::size_t payload_len = 0);

// ARP reply claiming `claimed_ip_nbo` for `egress_mac`, addressed to the
// requester.
std::vector<uint8_t> build_arp_reply(const Mac& client_mac, std::uint32_t claimed_ip_nbo,
                                     const Mac& egress_mac, std::uint32_t client_ip_nbo);

// User-space egress for decrypted adapter frames (OpenVPN-server style NAT).
// Instead of writing frames to a local TAP segment where they would die on an
// isolated virtual link, the forwarder terminates each flow with real sockets
// on this host and bridges bytes between the tunnel and the physical network:
//   - IPv4 TCP : client-side handshake is synthesized; payload bytes are
//                extracted in order from the client's segments and written to
//                a real outbound connection (and back), so sequence spaces of
//                the two independent handshakes never mix.
//   - IPv6 TCP/UDP: same bridging as above; the IP family of each flow is
//                taken from its frame (IPv4 or IPv6), sockets and return
//                frames follow it.
//   - IPv4 UDP : datagram relay over a per-flow socket, replies re-addressed
//                to the client.
//   - ARP      : requests are answered with a synthesized reply so the client
//                can resolve its virtual gateway at layer 2.
//   - ICMPv4   : echo requests addressed to the virtual gateway IP (default
//                10.8.0.1, settable via set_gateway_ip) are answered with a
//                synthesized echo reply; every other ICMP message is consumed
//                and dropped — forwarding it would need raw sockets or kernel
//                forwarding, which normal permissions do not grant.
//   - IPv4 fragments: datagrams split by an upstream router are reassembled
//                (per src/dst/id, capped in count/bytes, expired by the
//                sweeper) and only then dispatched to TCP/UDP.
// Only outbound connect() calls are used — no raw sockets, no binding of
// privileged ports, no routing-table changes — therefore it runs with normal
// (non-elevated) permissions. Everything else is not consumed and falls
// through to the legacy adapter write.
//
// All public methods must be invoked from the owning io_context's thread: the
// node delivers tunnel frames on its io_context, and every socket handler in
// this class runs there too, so no locking is needed by design.
class EgressForwarder {
public:
    explicit EgressForwarder(asio::io_context& io);
    ~EgressForwarder();

    void set_sender(FrameSender sender) { sender_ = std::move(sender); }

    // The virtual gateway IP this exit answers for (ICMP echo). Defaults to
    // 10.8.0.1, the convention of the 10.8.0.0/24 client network; deployments
    // with a different virtual subnet set it explicitly.
    void set_gateway_ip(asio::ip::address ip) {
        if (ip.is_v4()) gateway_ip_nbo_ = ip.to_v4().to_uint();
    }

    // Tuning knobs (defaults suit normal deployments; tests tighten them for
    // deterministic reaping). Seconds a partial fragment reassembly may live.
    void set_fragment_timeout(double seconds) { fragment_timeout_ = seconds; }
    // How often the idle-flow / stale-fragment sweeper runs.
    void set_sweep_interval(std::chrono::milliseconds interval) {
        sweep_interval_ = interval;
    }

    // Attempt to consume one decrypted Ethernet-II frame. `owner_peer` is the
    // identity of the tunnel peer that sent it: every flow created from this
    // frame binds return traffic to exactly that peer (multi-client exits).
    // Returns true when the frame was accepted (flow advanced, reply
    // sent/queued, or dropped by an explicit policy with a log line), false
    // when it is not forwardable and should fall through to the adapter write.
    bool handle_frame(const std::uint8_t* data, std::size_t len,
                      const std::vector<uint8_t>& owner_peer);

    [[nodiscard]] std::size_t flow_count() const;

private:
    struct FlowKey {
        asio::ip::address client_addr; // v4 or v6
        asio::ip::address server_addr; // v4 or v6
        std::uint16_t client_port = 0; // host order
        std::uint16_t server_port = 0; // host order
        std::uint8_t proto = 0;

        bool operator==(const FlowKey&) const = default;
    };
    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& k) const noexcept;
    };

    // One in-progress IPv4 reassembly, keyed by (src, dst, id).
    struct FragKey {
        asio::ip::address src;
        asio::ip::address dst;
        std::uint16_t id = 0;
        bool operator==(const FragKey&) const = default;
    };
    struct FragKeyHash {
        std::size_t operator()(const FragKey& k) const noexcept;
    };
    struct FragEntry {
        asio::ip::address src;
        asio::ip::address dst;
        std::uint8_t proto = 0;
        std::map<std::size_t, std::vector<uint8_t>> pieces; // byte offset -> payload
        std::size_t total_len = 0; // known once the last fragment (MF=0) arrives
        std::size_t bytes = 0;     // stored payload bytes (cap enforcement)
        double deadline = 0.0;
    };

    void start_sweeper();
    void arm_sweeper();
    void sweep_once();

    // Frame dispatch (called from handle_frame). owner_peer is bound to any
    // flow created so return traffic goes back to the originating client.
    void handle_tcp(const Mac& client_mac, const asio::ip::address& c_addr,
                    const asio::ip::address& srv_addr, std::uint16_t cp, std::uint16_t sp,
                    const std::uint8_t* l4, std::size_t l4_len,
                    const std::vector<uint8_t>& owner_peer);
    void handle_udp(const Mac& client_mac, const asio::ip::address& c_addr,
                    const asio::ip::address& srv_addr, std::uint16_t cp, std::uint16_t sp,
                    const std::uint8_t* payload, std::size_t plen,
                    const std::vector<uint8_t>& owner_peer);

    // TCP flow lifecycle.
    void start_connect(std::shared_ptr<TcpFlow> f);
    void on_connect_done(std::weak_ptr<TcpFlow> w, const asio::error_code& ec);
    void accept_client_data(std::shared_ptr<TcpFlow> f, std::uint32_t seq,
                            const std::uint8_t* payload, std::size_t plen);
    void drain_ooo(std::shared_ptr<TcpFlow> f);
    void append_pending(std::shared_ptr<TcpFlow> f, const std::uint8_t* p, std::size_t n);
    void try_flush(std::weak_ptr<TcpFlow> w);
    void start_server_read(std::weak_ptr<TcpFlow> w);
    void deliver_server_bytes(std::shared_ptr<TcpFlow> f);
    void send_ack_to_client(const std::shared_ptr<TcpFlow>& f, std::uint16_t extra_flags = 0);
    void abort_flow(const std::shared_ptr<TcpFlow>& f, bool reset_client);

    // UDP flow lifecycle.
    void start_udp_recv(std::weak_ptr<UdpFlow> w);
    void abort_udp(const std::shared_ptr<UdpFlow>& f);

    // ARP (owner_peer: the client that issued the request).
    bool handle_arp(const std::uint8_t* data, std::size_t len,
                    const std::vector<uint8_t>& owner_peer);

    // ICMPv4: echo requests to the gateway IP are answered; all other types
    // are consumed (documented above). `l4` is the complete ICMP message.
    void handle_icmp(const Mac& client_mac, std::uint32_t c_nbo, std::uint32_t s_nbo,
                     const std::uint8_t* l4, std::size_t l4_len,
                     const std::vector<uint8_t>& owner_peer);

    // Shared transport dispatch for whole datagrams (v4/v6 paths and fragment
    // reassembly). Returns the consume/fall-through decision.
    bool dispatch_l4(const Mac& client_mac, const asio::ip::address& c_addr,
                     const asio::ip::address& srv_addr, std::uint8_t proto,
                     const std::uint8_t* l4, std::size_t l4_len,
                     const std::vector<uint8_t>& owner_peer);

    // IPv4 fragment reassembly: `ip` is the fragment's IPv4 header and
    // `total_len` its declared total length (header + payload).
    bool handle_fragment(const Mac& client_mac, const std::uint8_t* ip,
                         std::uint16_t total_len, std::size_t frame_ip_len,
                         const std::vector<uint8_t>& owner_peer);

    // Frame emission to a specific client peer (returns false when the
    // tunnel cannot carry it).
    bool emit(const std::vector<uint8_t>& frame, const std::vector<uint8_t>& peer) const;

    asio::io_context& io_;
    FrameSender sender_;
    // Virtual gateway IP in network byte order (default 10.8.0.1).
    std::uint32_t gateway_ip_nbo_ = 0x0A080001u;
    double fragment_timeout_ = 5.0;                  // seconds
    std::chrono::milliseconds sweep_interval_{std::chrono::seconds(30)};

    using TcpMap = std::unordered_map<FlowKey, std::shared_ptr<TcpFlow>, FlowKeyHash>;
    using UdpMap = std::unordered_map<FlowKey, std::shared_ptr<UdpFlow>, FlowKeyHash>;
    using FragMap = std::unordered_map<FragKey, FragEntry, FragKeyHash>;
    TcpMap tcp_flows_;
    UdpMap udp_flows_;
    FragMap fragments_;

    asio::steady_timer sweeper_;
    bool sweeping_ = false;
};

} // namespace pqvpn::egress

#endif // PQVPN_EGRESS_FORWARDER_HPP
