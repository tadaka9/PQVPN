#include <asio.hpp>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>

#include "platform/adapter.hpp"
#ifdef _WIN32
#include "platform/windows_adapter.hpp"
#include "platform/windows_routes.hpp"
#include "routing/peer_route_manager.hpp"
#endif

#include "routing/route_transaction.hpp"

#include "config_module.hpp"
#include "egress_forwarder.hpp"
#include "logging_module.hpp"
#include "metrics_module.hpp"
#include "network_module.hpp"
#include "node_module.hpp"
#include "serialization_module.hpp"
#include "external_tunnel_process.hpp"

namespace {

struct CliArgs {
    std::string config_path = "config.json";
    std::string log_level = "info";
    bool smoke_test = false;
    bool validate_config = false;
    bool print_config = false;
    bool platform_info = false;
    bool version = false;
    std::string strangenet_room;
    std::string strangenet_peer;
    bool help = false;
#ifdef _WIN32
    bool no_tunnel = false;
    std::string tunnel_device;
#endif
};

void print_usage(const char* program) {
    std::cout
        << "Usage: " << program << " [--config PATH] [--log-level LEVEL] [--smoke-test]\n\n"
        << "Default mode starts the PQVPN node runtime and remains active until Ctrl+C/SIGTERM.\n"
        << "  -c, --config PATH       Configuration file path (default: config.json)\n"
        << "      --log-level LEVEL   spdlog level hint (default: info)\n"
        << "      --smoke-test        Load/serialize config and exit\n"
        << "      --validate-config   Validate configuration and exit\n"
        << "      --print-config      Print normalized configuration and exit\n"
        << "      --platform-info     Show OS-specific tunnel capabilities\n"
        << "      --version           Show the PQVPN build version\n"
        << "      --strangenet-room NAME  Join a bounded peer conversation room\n"
        << "      --strangenet-peer HEX  Authenticated peer identity for the room\n"
#ifdef _WIN32
        << "      --tunnel-device PATH  PQVPN driver device (default: \\\\.\\PQVPN_TUN0)\n"
        << "      --no-tunnel          Run without the PQVPN tunnel adapter\n"
#endif
        << "  -h, --help              Show this help\n";
}

std::optional<CliArgs> parse_args(int argc, char** argv) {
    CliArgs args;
    for (int index = 1; index < argc; ++index) {
        const std::string value = argv[index];
        if (value == "-h" || value == "--help") {
            args.help = true;
        } else if (value == "--smoke-test") {
            args.smoke_test = true;
        } else if (value == "--validate-config") {
            args.validate_config = true;
        } else if (value == "--print-config") {
            args.print_config = true;
        } else if (value == "--platform-info") {
            args.platform_info = true;
        } else if (value == "--version") {
            args.version = true;
        } else if (value == "--strangenet-room" || value == "--strangenet-peer") {
            if (++index >= argc) { std::cerr << value << " requires a value\n"; return std::nullopt; }
            if (value == "--strangenet-room") args.strangenet_room = argv[index];
            else args.strangenet_peer = argv[index];
#ifdef _WIN32
        } else if (value == "--no-tunnel") {
            args.no_tunnel = true;
        } else if (value == "--tunnel-device") {
            if (++index >= argc) {
                std::cerr << value << " requires a device path\n";
                return std::nullopt;
            }
            args.tunnel_device = argv[index];
#endif
        } else if (value == "-c" || value == "--config") {
            if (++index >= argc) {
                std::cerr << value << " requires a path\n";
                return std::nullopt;
            }
            args.config_path = argv[index];
        } else if (value == "--log-level") {
            if (++index >= argc) {
                std::cerr << value << " requires a level\n";
                return std::nullopt;
            }
            args.log_level = argv[index];
        } else {
            std::cerr << "Unknown argument: " << value << "\n";
            return std::nullopt;
        }
    }
    if (args.strangenet_room.empty() != args.strangenet_peer.empty()) {
        std::cerr << "--strangenet-room and --strangenet-peer must be used together\n";
        return std::nullopt;
    }
    return args;
}

std::optional<std::vector<std::uint8_t>> decode_peer_id(const std::string& value) {
    if (value.size() != 64) return std::nullopt;
    std::vector<std::uint8_t> decoded;
    decoded.reserve(32);
    auto nibble = [](const char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t index = 0; index < value.size(); index += 2) {
        const int high = nibble(value[index]), low = nibble(value[index + 1]);
        if (high < 0 || low < 0) return std::nullopt;
        decoded.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return decoded;
}

void print_platform_info() {
#if defined(_WIN32)
    std::cout << "os=windows\ntunnel=pqvpn-native-ndis\nminimum=windows-10\n";
#elif defined(__APPLE__)
    std::cout << "os=macos\ntunnel=network-extension-boundary\n";
#elif defined(__linux__)
    std::cout << "os=linux\ntunnel=/dev/net/tun\n";
#else
    std::cout << "os=unknown\ntunnel=unsupported\n";
#endif
    std::cout << "transport=udp\nadaptive-policy=pqtp-udp-tcp\n";
}

int run_smoke_test(const CliArgs& args) {
    using pqvpn::logging::Logger;
    using pqvpn::metrics::MetricsRegistry;

    Logger::info("PQVPN Node Smoke Test Starting...");
    MetricsRegistry::instance().increment_counter("node_smoke_test_total");

    auto config_result = pqvpn::config::load_config(args.config_path);
    if (!config_result) {
        Logger::error("Error loading configuration: {}", args.config_path);
        MetricsRegistry::instance().increment_counter("config_load_failure_total");
        return 1;
    }

    Logger::info("Configuration loaded successfully.");
    MetricsRegistry::instance().increment_counter("config_load_success_total");
    Logger::info("Security strict verification: {}", config_result->security.strict_sig_verify ? "true" : "false");
    Logger::info("Network bind: {}:{}", config_result->network.bind_address, config_result->network.port);

    Logger::info("\n--- Serialized Config (JSON) ---");
    const std::string json = pqvpn::serialization::JsonSerializer::serialize(*config_result);
    Logger::info("{}", json);

    Logger::info("\n--- Deserializing Back from JSON ---");
    auto deserialized_result = pqvpn::serialization::JsonSerializer::deserialize(json);
    if (!deserialized_result) {
        Logger::error("Deserialization Error: {}", deserialized_result.error());
        MetricsRegistry::instance().increment_counter("config_deserialization_failure_total");
        return 1;
    }

    Logger::info("Deserialization successful.");
    MetricsRegistry::instance().increment_counter("config_deserialization_success_total");
    Logger::info("Recovered Network port: {}", deserialized_result->network.port);
    Logger::info("Recovered Security strict and TOFU: {}, {}",
                 deserialized_result->security.strict_sig_verify ? "true" : "false",
                 deserialized_result->security.tofu ? "true" : "false");

    Logger::info("\n--- Metrics Summary ---");
    MetricsRegistry::instance().dump_metrics();
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    auto parsed = parse_args(argc, argv);
    if (!parsed) {
        print_usage(argv[0]);
        return 2;
    }

    const CliArgs args = *parsed;
    if (args.help) {
        print_usage(argv[0]);
        return 0;
    }

    if (args.version) {
        std::cout << "PQVPN 0.0.1-alpha\n";
        return 0;
    }
    if (args.platform_info) {
        print_platform_info();
        return 0;
    }

    if (args.validate_config || args.print_config) {
        auto checked = pqvpn::config::load_config(args.config_path);
        if (!checked) {
            std::cerr << "Invalid PQVPN configuration: " << args.config_path << "\n";
            return 1;
        }
        if (args.print_config) {
            std::cout << pqvpn::serialization::JsonSerializer::serialize(*checked) << "\n";
        } else {
            std::cout << "Configuration valid: " << args.config_path << "\n";
        }
        return 0;
    }

    if (args.smoke_test) {
        return run_smoke_test(args);
    }

    // Start the PQVPN node runtime with the provided configuration
    auto config = pqvpn::config::load_config(args.config_path);
    if (!config) {
        std::cerr << "Failed to load config: " << args.config_path << "\n";
        return 1;
    }

    // Start the PQVPN node runtime with the provided configuration
    asio::io_context io;
    auto node = std::make_shared<pqvpn::PQVPNNode>(io, args.config_path);
    node->configure_traffic_shaping(config->traffic_shaping);

    // Apply optional runtime tuning from config "tuning". Omitted fields keep
    // the protocol defaults baked into PQVPNNode, so existing configs behave
    // exactly as before; load_config already rejected non-positive values.
    if (config->tuning.session_timeout_seconds) {
        node->session_timeout = *config->tuning.session_timeout_seconds;
    }
    if (config->tuning.keepalive_interval_seconds) {
        node->keepalive_interval = *config->tuning.keepalive_interval_seconds;
    }
    if (config->tuning.liveness_window_seconds) {
        node->liveness_window = *config->tuning.liveness_window_seconds;
    }
    if (config->tuning.handshake_timeout_seconds) {
        node->handshake_timeout = *config->tuning.handshake_timeout_seconds;
    }
    if (config->tuning.bootstrap_retry_seconds) {
        node->bootstrap_retry_interval = *config->tuning.bootstrap_retry_seconds;
    }
    if (config->tuning.replay_window_size) {
        node->replay_window_size = static_cast<size_t>(*config->tuning.replay_window_size);
    }

    // Load (or generate and persist) this node's hybrid identity: Ed25519 +
    // X25519 + ML-KEM-1024 + ML-DSA-87. Without it the node cannot sign HELLO/
    // S1/S2 or complete a handshake, so fail closed instead of running mute.
    if (!node->load_or_create_identity()) {
        std::cerr << "Failed to load or create node identity\n";
        return 1;
    }

    // Apply the operator's security policy: TOFU admission and the known-peers
    // store location. (The allowlist is intentionally not wired into peer-id
    // matching — it holds addresses, while admission keys on peer identity.)
    node->set_tofu_enabled(config->security.tofu);
    node->known_peers_file_ = config->security.known_peers_file;
    try {
        node->load_known_peers();
    } catch (const std::exception& error) {
        std::cerr << "warning: known-peers load failed: " << error.what() << "\n";
    }

    // Establish this node's stable identity before it can relay or deliver
    // locally: handle_relay binds its AAD to peer_hash8(my_id) and requires it.
    // When no ed25519 key is loaded the node cannot peel onions — say so
    // explicitly instead of silently rejecting every relay (see establish_identity).
    if (!node->establish_identity()) {
        std::cerr << "warning: no node identity established (no ed25519 key); "
                  << "onion relay and local delivery will be rejected\n";
    }
    std::unique_ptr<pqvpn::tunnel::ExternalTunnelProcess> external_tunnel;
    if (config->tunnel.plugin != "pqvpn") {
        try {
            const auto backend = pqvpn::tunnel::backend_from_string(config->tunnel.plugin);
            auto spec = pqvpn::tunnel::make_external_process_spec(backend, config->tunnel.config_path);
            external_tunnel = std::make_unique<pqvpn::tunnel::ExternalTunnelProcess>(std::move(spec));
            external_tunnel->start();
        } catch (const std::exception& error) {
            std::cerr << "Failed to start tunnel plugin: " << error.what() << "\n";
            return 1;
        }
    }
    pqvpn::network::UdpListener listener(io, config->network);
    listener.set_receive_handler([&io, node](std::vector<uint8_t> packet, const asio::ip::udp::endpoint& sender) {
        asio::co_spawn(io, node->datagram_received(std::move(packet), sender), asio::detached);
    });
    if (const auto started = listener.start(); !started) {
        std::cerr << "Failed to start UDP listener\n";
        return 1;
    }
    node->transport = &listener.socket();
    if (config->external_transport) {
        asio::error_code error;
        listener.socket().connect(config->external_transport->endpoint(), error);
        if (error) {
            std::cerr << "Cannot attach external UDP transport: " << error.message() << "\n";
            return 1;
        }
    }

    // Bootstrap contact: actively send signed HELLOs toward configured peers
    // until a session with each is established (the deterministic initiator
    // then drives S1/S2). Skipped entirely when no bootstrap list is set.
    if (!config->bootstrap.empty()) {
        std::vector<asio::ip::udp::endpoint> bootstrap_endpoints;
        for (const auto& peer : config->bootstrap) {
            std::error_code address_error;
            const auto address = asio::ip::make_address(peer.host, address_error);
            if (address_error || peer.port <= 0 || peer.port > 65535) {
                std::cerr << "skipping invalid bootstrap entry "
                          << peer.host << ":" << peer.port << "\n";
                continue;
            }
            bootstrap_endpoints.emplace_back(address, static_cast<uint16_t>(peer.port));
        }
        if (!bootstrap_endpoints.empty()) {
            asio::co_spawn(io, node->bootstrap_peers(bootstrap_endpoints), asio::detached);
        }
    }

    // Per-OS tunnel adapter: PQVPN's driver on Windows, /dev/net/tun on Linux, and the
    // Network Extension boundary on macOS (see src/platform/adapter.hpp).
    std::unique_ptr<pqvpn::platform::Adapter> adapter;
#ifdef _WIN32
    pqvpn::routing::RouteTransaction route_plan;
    pqvpn::platform::WindowsRouteBackend route_backend;
    // Declared with the other route state (not inside the TAP block) so the
    // signal handler can roll back peer exclusions on shutdown. Safe to leave
    // unused when no_tunnel is set: remove_all() on an empty manager succeeds.
    pqvpn::routing::PeerRouteManager peer_routes(route_backend);
    if (!args.no_tunnel) {
        adapter = pqvpn::platform::make_adapter(args.tunnel_device);
    }
#else
    // Config "tunnel.interface_name" selects the TUN device name; empty keeps
    // the kernel-selected default.
    adapter = pqvpn::platform::make_adapter(config->tunnel.interface_name);
#endif

    // User-space egress (OpenVPN-server style NAT): when enabled, decrypted
    // tunnel frames are terminated with real outbound sockets on this host and
    // bridged to the physical network instead of being written to a local TAP
    // segment where they would die. Only outbound connect() calls are used, so
    // it runs without elevation (see egress_forwarder.hpp).
    std::unique_ptr<pqvpn::egress::EgressForwarder> egress;
    if (config->egress.enabled) {
        egress = std::make_unique<pqvpn::egress::EgressForwarder>(io);
        auto* eg = egress.get();
        eg->set_sender([node](const std::vector<uint8_t>& frame,
                              const std::vector<uint8_t>& peer) -> bool {
            // Return traffic goes back to the SPECIFIC client that owns the
            // flow (bound when its first frame was seen), so one exit node
            // can serve several clients at once.
            if (peer.empty()) return false;
            return node->send_tunnel_packet(peer, std::span<const uint8_t>(frame));
        });
    }

    bool adapter_active = false;
    if (adapter) {
        if (adapter->open([node](pqvpn::platform::Adapter::Packet frame) {
                // Adapter -> tunnel: forward to the selected established session.
                asio::co_spawn(node->get_io_context(),
                    node->forward_adapter_packet(std::move(frame)), asio::detached);
            })) {
            adapter_active = true;
            std::cout << "tunnel adapter active: " << adapter->describe() << "\n";
        } else {
#ifdef _WIN32
            // A VPN node without its TAP device is useless on Windows; fail closed.
            listener.stop();
            return 1;
#else
            std::cerr << "tunnel adapter unavailable; continuing in UDP-only mode\n";
#endif
        }
    }

    // Tunnel -> local delivery sink. Egress (when enabled) gets first claim on
    // every decrypted frame and consumes what it can forward; the rest falls
    // through to the legacy TAP write so non-forwardable traffic keeps its old
    // behavior. Installed even without an adapter: a UDP-only node with egress
    // enabled is still a functional exit (frames never touch a local device).
    auto* raw_adapter = adapter_active ? adapter.get() : nullptr;
    auto* eg_ptr = egress.get();
    node->set_tunnel_packet_handler([raw_adapter, eg_ptr](std::vector<uint8_t> frame,
                                                           const std::vector<uint8_t>& src_peer) {
        if (eg_ptr && !frame.empty()) {
            // Egress binds return traffic to the client that sent this frame.
            if (eg_ptr->handle_frame(frame.data(), frame.size(), src_peer)) return; // consumed/answered
        }
        // Tunnel -> adapter. The adapter may already be closed during shutdown;
        // drop the frame instead of unwinding the coroutine.
        if (raw_adapter && !raw_adapter->write(frame)) { /* dropped */ }
    });

    if (!args.strangenet_room.empty()) {
        const auto peer = decode_peer_id(args.strangenet_peer);
        if (!peer || args.strangenet_room.size() > pqvpn::strangenet::kMaxRoomBytes) {
            std::cerr << "Invalid StrangeNet room or peer identity\n";
            return 2;
        }
        node->set_strangenet_handler([](const pqvpn::strangenet::Message& message,
                                        const std::vector<std::uint8_t>&) {
            std::cout << "\n[" << message.room << "] " << message.sender.substr(0, 12)
                      << ": " << message.text << "\n> " << std::flush;
        });
        const auto room = args.strangenet_room;
        std::thread([node, peer = *peer, room, &io] {
            std::uint64_t sequence = 0;
            std::string line;
            std::cout << "StrangeNet room '" << room << "' ready; messages send after the peer session is established.\n> " << std::flush;
            while (std::getline(std::cin, line)) {
                if (line == "/quit") break;
                if (line.empty() || line.size() > pqvpn::strangenet::kMaxMessageBytes) {
                    std::cout << "Message must contain 1.." << pqvpn::strangenet::kMaxMessageBytes << " bytes\n> " << std::flush;
                    continue;
                }
                const auto timestamp = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                asio::post(io, [node, peer, room, text = line, value = ++sequence, timestamp] {
                    if (!node->send_strangenet_message(peer, room, value, timestamp, text))
                        std::cerr << "StrangeNet send deferred: authenticated peer session is unavailable\n";
                    else
                        std::cout << "StrangeNet message accepted\n";
                });
                std::cout << "> " << std::flush;
            }
        }).detach();
    }

#ifdef _WIN32
    if (adapter_active) {
        try {

            // Route traffic through the adapter only when it actually has an
            // IPv4 address; otherwise a default route would blackhole. The row
            // is the Windows default route: destination 0.0.0.0 with a zero
            // mask (prefix length 0, matching every destination) and the
            // adapter address as next hop. A /32 here would match only the
            // literal 0.0.0.0 address and send no real traffic to the TAP.
            const auto adapter_route = pqvpn::platform::find_adapter_ipv4("PQVPN Tunnel");
            if (!adapter_route) {
                std::cerr << "PQVPN Tunnel has no IPv4 address; skipping route installation\n";
            } else {
                    // The tunnel default route would also capture this node's own UDP
                // transport: peer datagrams would enter the adapter, get
                // re-encrypted by the data path, and loop. Before it can win,
                // pin every known tunnel peer (and control-plane destination)
                // to the pre-VPN physical gateway with /32 host routes.
                const auto physical = pqvpn::platform::find_default_route(adapter_route->interface_index);
                if (!physical) {
                        std::cerr << "no pre-VPN default route found; skipping tunnel default route "
                              << "(installing it without peer exclusions would loop tunnel traffic)\n";
                } else {
                    pqvpn::routing::PeerRouteManager::PhysicalGateway gateway;
                    gateway.gateway = physical->ipv4;
                    gateway.interface_index = physical->interface_index;

                    // Optional IPv6 full tunnel: only when the adapter actually
                    // carries a usable (non-link-local) IPv6 address AND a
                    // physical IPv6 gateway exists to pin IPv6 peers out of the
                    // virtual default. Otherwise IPv6 is blackholed below.
                    const auto adapter6 =
                        pqvpn::platform::find_adapter_ipv6("PQVPN Tunnel");
                    bool full_tunnel_v6 = false;
                    if (adapter6) {
                        const auto physical6 = pqvpn::platform::find_default_route_v6(
                            adapter6->interface_index);
                        if (physical6) {
                            gateway.gateway6 = physical6->ipv4;
                            gateway.interface6 = physical6->interface_index;
                            full_tunnel_v6 = true;
                        }
                    }
                    peer_routes.set_physical_gateway(std::move(gateway));

                    // Exclude every address already known at startup...
                    bool exclusions_ok = true;
                    for (const auto& [peer_id, session] : node->sessions_by_peer_id) {
                        (void)peer_id;
                        if (!session || session->remote_addr.address().is_unspecified()) continue;
                        if (!peer_routes.add_peer(session->remote_addr).ok) exclusions_ok = false;
                    }
                    for (const auto& [peer_hex, info] : node->mesh.peers) {
                        (void)peer_hex;
                        if (info.address.address().is_unspecified()) continue;
                        if (!peer_routes.add_peer(info.address).ok) exclusions_ok = false;
                    }

                    // ...and keep the exclusions current as peers appear or go.
                    // A failed ADD is reported back: while the TAP default is
                    // active, admitting a peer without its /32 exclusion would
                    // loop that peer's transport through the adapter, so the
                    // node fails closed on it (registration rejected, session
                    // refused). Removals stay best-effort — teardown must not
                    // be blocked by cleanup failures; the manager keeps failed
                    // removals owned for retry.
                    node->set_peer_route_hook(
                        [&peer_routes](const asio::ip::udp::endpoint& address, const bool add) {
                            if (add) {
                                const auto result = peer_routes.add_peer(address);
                                if (!result.ok) {
                                    std::cerr << "peer route exclusion failed for "
                                              << address << ": " << result.error << "\n";
                                }
                                return result.ok;
                            }
                            const auto result = peer_routes.remove_peer(address);
                            if (!result.ok) {
                                std::cerr << "peer route removal failed for "
                                          << address << ": " << result.error << "\n";
                            }
                            return result.ok;
                        });

                    if (!exclusions_ok) {
                        // Incomplete exclusions are an aborted transaction: roll
                        // back the ones that did install and lift the admission
                        // gate, since no VPN default is active to protect against.
                        const auto cleanup = peer_routes.remove_all();
                        if (!cleanup.complete) {
                            std::cerr << "peer route cleanup incomplete: " << cleanup.error << "\n";
                        }
                        node->set_peer_route_hook(nullptr); // nothing left to gate on
                        std::cerr << "peer route exclusions incomplete; skipping TAP default route\n";
                    } else {
                        route_plan.add(pqvpn::routing::RouteEntry{
                            asio::ip::make_address_v4("0.0.0.0"), 0,
                            adapter_route->ipv4, adapter_route->interface_index});

                        if (full_tunnel_v6) {
                            // Route IPv6 through the adapter too, using its
                            // own global/ULA address as next hop.
                            route_plan.add(pqvpn::routing::RouteEntry{
                                asio::ip::make_address_v6("::"), 0,
                                adapter6->ipv4, adapter6->interface_index});
                            std::cout << "IPv6 default route installed through the PQVPN Tunnel adapter\n";
                        } else {
                            // No IPv6 in the tunnel: blackhole the IPv6 default
                            // through loopback so the host's global IPv6 address
                            // cannot keep leaking past the VPN.
                            route_plan.add(pqvpn::routing::RouteEntry{
                                asio::ip::make_address_v6("::"), 0,
                                asio::ip::make_address_v6("::1"), 0});
                            std::cout
                                << "IPv6 default route blackholed to prevent leakage\n";
                        }

                        if (const auto report = route_plan.commit(route_backend); report.committed) {
                            std::cout << "default route installed through the PQVPN Tunnel adapter\n";
                        } else {
                            // The default is down; drop the exclusions we just
                            // created so no owned routes survive a failed setup, and
                            // lift the admission gate — with no VPN default active
                            // there is nothing to protect against.
                            const auto cleanup = peer_routes.remove_all();
                            if (!cleanup.complete) {
                                std::cerr << "peer route cleanup incomplete: " << cleanup.error << "\n";
                            }
                            node->set_peer_route_hook(nullptr);
                            std::cerr << "route installation failed (" << report.error
                                << "); continuing without VPN routes\n";
                        }
                    }
                }
            }
        } catch (const std::exception& error) {
            // No owned routes may survive a failed setup, even if the failure
            // happened after some peer exclusions were installed.
            const auto peer_cleanup = peer_routes.remove_all();
            if (!peer_cleanup.complete) {
                std::cerr << "peer route cleanup incomplete: " << peer_cleanup.error << "\n";
            }
            std::cerr << "adapter route setup failed: " << error.what() << "\n";
            listener.stop();
            return 1;
        }
    }
#endif

    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](const asio::error_code&, int) {
#ifdef _WIN32
        if (adapter_active) {
            // Remove the installed routes before taking the adapter down, in
            // reverse build order: peer exclusions first, then the default.
            // Removal is idempotent, so this is safe even on partial installs.
            const auto peer_cleanup = peer_routes.remove_all();
            if (!peer_cleanup.complete) {
                std::cerr << "peer route cleanup incomplete: " << peer_cleanup.error << "\n";
            }
            const auto removal = route_plan.remove_all(route_backend);
            if (!removal.complete) {
                std::cerr << "route cleanup incomplete: " << removal.error << "\n";
            }
        }
#endif
        node->stop_traffic_shaping();
        node->transport = nullptr;
        listener.stop();
        if (adapter) adapter->close(); // idempotent per OS
        io.stop();
    });

    // Run session maintenance for the lifetime of the runtime. This loop is
    // what sends tunnel liveness probes, and select_tunnel_peer only trusts
    // peers that answered within LIVENESS_WINDOW — without it, idle sessions
    // expire after one window and adapter forwarding fails closed even though
    // every peer is healthy. It stops with the io_context on shutdown.
    asio::co_spawn(io, node->session_maintenance(), asio::detached);

    std::cout << "PQVPN Node Runtime started with config: " << args.config_path << "\n";
    io.run();
    std::cout << "PQVPN Node Runtime stopped.\n";

    return 0;
}
