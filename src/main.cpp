#include <asio.hpp>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#ifdef __linux__
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "platform/adapter.hpp"
#ifdef __linux__
#include "platform/linux_tun_framing.hpp"
#endif
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
#include "group_chat.hpp"
#include "serialization_module.hpp"
#include "external_tunnel_process.hpp"

namespace {

#ifdef __linux__
bool run_linux_network_manager(const char* action, const std::string& interface_name,
                               const std::string& exit_host, int exit_port) {
    if (interface_name.empty() || exit_host.empty() || exit_port <= 0) return false;
    const auto port = std::to_string(exit_port);
    const pid_t child = ::fork();
    if (child == 0) {
        constexpr const char* helper = "/usr/lib/pqvpn/pqvpn-linux-network";
        if (::geteuid() == 0) {
            ::execl(helper, "pqvpn-linux-network", action, interface_name.c_str(),
                    exit_host.c_str(), port.c_str(), nullptr);
        } else {
            ::execlp("pkexec", "pkexec", helper, action, interface_name.c_str(),
                     exit_host.c_str(), port.c_str(), nullptr);
        }
        _exit(127);
    }
    if (child < 0) return false;
    int status = 0;
    while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

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
    bool control_stdin = false;
    bool no_tunnel = false;
    bool help = false;
#ifdef _WIN32
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
        << "      --strangenet-room NAME  Join a bounded room; broadcasts to authenticated peers\n"
        << "      --strangenet-peer HEX   Optionally restrict the room to one peer identity\n"
        << "      --control-stdin      Accept newline-delimited GUI control commands\n"
        << "      --no-tunnel          Run as a UDP relay/exit without a local tunnel\n"
#ifdef _WIN32
        << "      --tunnel-device PATH  PQVPN driver device (default: \\\\.\\PQVPN_TUN0)\n"
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
        } else if (value == "--control-stdin") {
            args.control_stdin = true;
        } else if (value == "--strangenet-room" || value == "--strangenet-peer") {
            if (++index >= argc) { std::cerr << value << " requires a value\n"; return std::nullopt; }
            if (value == "--strangenet-room") args.strangenet_room = argv[index];
            else args.strangenet_peer = argv[index];
        } else if (value == "--no-tunnel") {
            args.no_tunnel = true;
#ifdef _WIN32
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
    if (args.strangenet_room.empty() && !args.strangenet_peer.empty()) {
        std::cerr << "--strangenet-peer requires --strangenet-room\n";
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

std::string encode_peer_id(const std::vector<std::uint8_t>& value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(value.size() * 2);
    for (const auto byte : value) {
        encoded.push_back(digits[byte >> 4]);
        encoded.push_back(digits[byte & 0x0f]);
    }
    return encoded;
}

bool valid_strangenet_room(const std::string& room) {
    if (room.empty() || room.size() > pqvpn::strangenet::kMaxRoomBytes) return false;
    return std::all_of(room.begin(), room.end(), [](const unsigned char character) {
        return std::isalnum(character) || character == '.' || character == '_' || character == '-';
    });
}

void emit_console_event(const nlohmann::json& event) {
    std::cout << "PQVPN_EVENT " << event.dump() << std::endl;
}

void print_platform_info() {
#if defined(_WIN32)
    std::cout << "os=windows\ntunnel=pqvpn-native-ndis\nminimum=windows-10\n";
    HANDLE driver = CreateFileW(L"\\\\.\\PQVPN_TUN0", GENERIC_READ | GENERIC_WRITE,
                                0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (driver != INVALID_HANDLE_VALUE) {
        std::cout << "driver=ready\n";
        CloseHandle(driver);
    } else {
        const auto error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) std::cout << "driver=access-denied\n";
        else if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            std::cout << "driver=not-installed\n";
        else std::cout << "driver=unavailable\n";
        std::cout << "driver-error=" << error << "\n";
    }
#elif defined(__APPLE__)
    std::cout << "os=macos\ntunnel=network-extension-boundary\ndriver=not-applicable\n";
#elif defined(__linux__)
    std::cout << "os=linux\ntunnel=/dev/net/tun\ndriver=not-applicable\n";
#else
    std::cout << "os=unknown\ntunnel=unsupported\ndriver=not-applicable\n";
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
    auto printable = *config_result;
    printable.security.known_peers_passphrase.reset();
    const std::string json = pqvpn::serialization::JsonSerializer::serialize(printable);
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
        std::cout << "PQVPN " << PQVPN_BUILD_VERSION << '\n';
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
            checked->security.known_peers_passphrase.reset();
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
    if (!config->tunnel.exit_host.empty()) {
        asio::error_code error;
        const auto address = asio::ip::make_address(config->tunnel.exit_host, error);
        if (error) {
            std::cerr << "tunnel.exit_host must be a numeric IP address: " << error.message() << "\n";
            return 1;
        }
        node->set_preferred_exit({address, static_cast<std::uint16_t>(config->tunnel.exit_port)});
    }
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
    if (!args.no_tunnel) {
#ifdef __linux__
        if (!run_linux_network_manager("prepare", config->tunnel.interface_name,
                                       config->tunnel.exit_host, config->tunnel.exit_port)) {
            std::cerr << "Cannot create the protected Linux TUN device\n";
            listener.stop();
            return 1;
        }
#endif
        adapter = pqvpn::platform::make_adapter(config->tunnel.interface_name);
    }
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
        eg->set_allow_private_destinations(config->egress.allow_private_destinations);
        std::cout << "user-space egress active; private destinations "
                  << (config->egress.allow_private_destinations ? "allowed" : "blocked") << "\n";
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
    bool linux_network_active = false;
    if (adapter) {
        if (adapter->open([node](pqvpn::platform::Adapter::Packet frame) {
                // Adapter -> tunnel: forward to the selected established session.
#ifdef __linux__
                auto ethernet = pqvpn::platform::tun_packet_to_ethernet(frame);
                if (!ethernet) return;
                frame = std::move(*ethernet);
#endif
                asio::co_spawn(node->get_io_context(),
                    node->forward_adapter_packet(std::move(frame)), asio::detached);
            })) {
            adapter_active = true;
            std::cout << "tunnel adapter active: " << adapter->describe() << "\n";
#ifdef __linux__
            if (!run_linux_network_manager("up", config->tunnel.interface_name,
                                           config->tunnel.exit_host, config->tunnel.exit_port)) {
                std::cerr << "Linux route/DNS/killswitch setup failed; refusing an unprotected connection\n";
                adapter->close();
                listener.stop();
                return 1;
            }
            linux_network_active = true;
            emit_console_event({{"event", "tunnel.ready"}, {"ipv4", "full"},
                                {"ipv6", "blocked"}, {"dns", "tunnel"},
                                {"fail_closed", true}});
#endif
        } else {
#if defined(_WIN32) || defined(__linux__)
            // A client without its tunnel device must never imply protection.
            std::cerr << "Cannot open the PQVPN tunnel adapter. Install the PQVPN "
                         "driver (and run this node elevated), or start with "
                         "--no-tunnel to test peer connectivity without tunneling.\n";
            listener.stop();
#ifdef __linux__
            run_linux_network_manager("down", config->tunnel.interface_name,
                                      config->tunnel.exit_host, config->tunnel.exit_port);
#endif
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
        if (raw_adapter) {
#ifdef __linux__
            auto packet = pqvpn::platform::ethernet_to_tun_packet(frame);
            if (!packet || !raw_adapter->write(*packet)) { /* dropped */ }
#else
            if (!raw_adapter->write(frame)) { /* dropped */ }
#endif
        }
    });

    auto shutdown = std::make_shared<std::function<void()>>();
    if (!args.strangenet_room.empty() || args.control_stdin) {
        const auto initial_peer = args.strangenet_peer.empty() || args.strangenet_peer == "auto"
            ? std::optional<std::vector<std::uint8_t>>{}
            : decode_peer_id(args.strangenet_peer);
        if ((!args.strangenet_room.empty() && !valid_strangenet_room(args.strangenet_room)) ||
            (!args.strangenet_peer.empty() && args.strangenet_peer != "auto" && !initial_peer)) {
            std::cerr << "Invalid StrangeNet room or peer identity\n";
            return 2;
        }

        struct StrangeNetRuntime {
            std::string room;
            std::optional<std::vector<std::uint8_t>> peer;
            std::vector<std::vector<std::uint8_t>> group_peers;
            // Sequence numbers remain monotonic for every room during this
            // authenticated process lifetime, including leave/rejoin cycles.
            std::unordered_map<std::string, std::uint64_t> sequences;
            pqvpn::strangenet::FloodGuard outbound_flood;
        };
        auto strange = std::make_shared<StrangeNetRuntime>();
        strange->room = args.strangenet_room;
        strange->peer = initial_peer;

        node->set_peer_session_handler([node_view = node.get()](const std::vector<std::uint8_t>& peer,
                                                               const asio::ip::udp::endpoint& endpoint,
                                                               const bool connected) {
            emit_console_event({{"event", connected ? "peer.connected" : "peer.disconnected"},
                                {"peer", encode_peer_id(peer)},
                                {"ready", connected || node_view->select_tunnel_peer().has_value()},
                                {"endpoint", endpoint.address().to_string() + ":" +
                                             std::to_string(endpoint.port())}});
        });

        node->set_strangenet_handler([strange, node_view = node.get()](const pqvpn::strangenet::Message& message,
                                                                      const std::vector<std::uint8_t>& peer) {
            if (strange->room.empty() || message.room != strange->room ||
                (strange->peer && peer != *strange->peer)) return;
            if (message.kind == pqvpn::strangenet::Kind::Acknowledgement) {
                emit_console_event({{"event", "strangenet.delivered"},
                                    {"room", message.room}, {"sequence", message.reply_to},
                                    {"peer", encode_peer_id(peer)}});
                return;
            }
            const char* event_name = message.kind == pqvpn::strangenet::Kind::Sticker
                ? "strangenet.sticker" : (message.kind == pqvpn::strangenet::Kind::Reaction
                    ? "strangenet.reaction" : "strangenet.message");
            emit_console_event({{"event", event_name},
                                {"room", message.room},
                                {"sender", message.sender},
                                {"timestamp_ms", message.timestamp_ms},
                                {"sequence", message.sequence},
                                {"reply_to", message.reply_to},
                                {"text", message.text}});
            const auto timestamp = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            auto& ack_sequence = strange->sequences[message.room];
            node_view->send_strangenet_message(peer, message.room, ++ack_sequence, timestamp, {},
                pqvpn::strangenet::Kind::Acknowledgement, message.sequence);
        });

        if (!strange->room.empty()) {
            emit_console_event({{"event", "strangenet.joined"}, {"room", strange->room},
                                {"peer", args.strangenet_peer.empty() ? "auto" : args.strangenet_peer}});
        }
        std::thread([node, strange, control = args.control_stdin, shutdown, &io] {
            std::string line;
            while (std::getline(std::cin, line)) {
                if (control) {
                    try {
                        const auto command = nlohmann::json::parse(line);
                        if (!command.is_object() || !command.contains("command") ||
                            !command.at("command").is_string()) {
                            emit_console_event({{"event", "control.error"}, {"message", "invalid command"}});
                            continue;
                        }
                        asio::post(io, [node, strange, command, shutdown] {
                            const auto name = command.at("command").get<std::string>();
                            if (name == "node.shutdown") {
                                if (*shutdown) (*shutdown)();
                            } else if (name == "strangenet.join") {
                                const auto room = command.value("room", std::string{});
                                const auto peer_text = command.value("peer", std::string{"auto"});
                                const auto peer = peer_text == "auto"
                                    ? std::optional<std::vector<std::uint8_t>>{}
                                    : decode_peer_id(peer_text);
                                std::vector<std::vector<std::uint8_t>> group_peers;
                                std::vector<std::string> group_text;
                                if (command.contains("peers")) {
                                    if (!command.at("peers").is_array()) {
                                        emit_console_event({{"event", "control.error"},
                                                            {"message", "group peers must be an array"}});
                                        return;
                                    }
                                    for (const auto& value : command.at("peers")) {
                                        if (!value.is_string()) { group_text.clear(); break; }
                                        group_text.push_back(value.get<std::string>());
                                    }
                                    const auto local = node->my_id_ ? encode_peer_id(*node->my_id_) : std::string{};
                                    if (!pqvpn::group_chat::canonicalize_members(local, group_text)) {
                                        emit_console_event({{"event", "control.error"},
                                                            {"message", "a group requires two to 63 distinct authenticated peers"}});
                                        return;
                                    }
                                    for (const auto& value : group_text) group_peers.push_back(*decode_peer_id(value));
                                }
                                if (!valid_strangenet_room(room) || (peer_text != "auto" && !peer)) {
                                    emit_console_event({{"event", "control.error"},
                                                        {"message", "invalid StrangeNet room or peer"}});
                                    return;
                                }
                                if (!strange->room.empty() && strange->room != room)
                                    node->leave_strangenet_room(strange->room);
                                strange->room = room;
                                strange->peer = peer;
                                strange->group_peers = std::move(group_peers);
                                emit_console_event({{"event", "strangenet.joined"},
                                                    {"room", room}, {"peer", peer_text},
                                                    {"group_size", strange->group_peers.empty() ? 0 : strange->group_peers.size() + 1}});
                            } else if (name == "strangenet.leave") {
                                const auto room = strange->room;
                                if (!room.empty()) node->leave_strangenet_room(room);
                                strange->room.clear();
                                strange->peer.reset();
                                strange->group_peers.clear();
                                emit_console_event({{"event", "strangenet.left"}, {"room", room}});
                            } else if (name == "strangenet.send" || name == "strangenet.sticker" ||
                                       name == "strangenet.react") {
                                const auto text = command.value("text", std::string{});
                                const auto reply_to = command.value("reply_to", std::uint64_t{0});
                                if (strange->room.empty() || text.empty() ||
                                    text.size() > pqvpn::strangenet::kMaxMessageBytes ||
                                    (name == "strangenet.react" && reply_to == 0)) {
                                    emit_console_event({{"event", "control.error"},
                                                        {"message", "join a room and send 1..2048 bytes"}});
                                    return;
                                }
                                const auto timestamp = static_cast<std::uint64_t>(
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch()).count());
                                const auto kind = name == "strangenet.sticker" ? pqvpn::strangenet::Kind::Sticker
                                    : (name == "strangenet.react" ? pqvpn::strangenet::Kind::Reaction
                                                                   : pqvpn::strangenet::Kind::Text);
                                const auto monotonic_ms = static_cast<std::uint64_t>(
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch()).count());
                                const auto flood = strange->outbound_flood.accept(
                                    {strange->room, "local", 1, timestamp, text, kind, reply_to}, monotonic_ms);
                                if (!flood.allowed) {
                                    emit_console_event({{"event", "strangenet.rate_limited"},
                                                        {"message", "StrangeNet antiflood limit reached"},
                                                        {"retry_after_ms", flood.retry_after_ms}});
                                    return;
                                }
                                auto& sequence = strange->sequences[strange->room];
                                const auto current = ++sequence;
                                std::size_t recipients = 0;
                                if (!strange->group_peers.empty()) {
                                    recipients = node->send_strangenet_group(strange->group_peers,
                                        strange->room, current, timestamp, text, kind, reply_to);
                                } else if (strange->peer) {
                                    recipients = node->send_strangenet_message(*strange->peer, strange->room,
                                        current, timestamp, text, kind, reply_to) ? 1u : 0u;
                                } else {
                                    recipients = node->broadcast_strangenet_message(strange->room, current,
                                        timestamp, text, kind, reply_to);
                                }
                                if (recipients == 0) {
                                    emit_console_event({{"event", "strangenet.deferred"},
                                                        {"message", "authenticated peer session is unavailable"}});
                                } else {
                                    emit_console_event({{"event", "strangenet.sent"},
                                                        {"room", strange->room}, {"text", text},
                                                        {"sequence", current}, {"recipients", recipients},
                                                        {"kind", name == "strangenet.sticker" ? "sticker"
                                                                  : (name == "strangenet.react" ? "reaction" : "text")}});
                                }
                            } else {
                                emit_console_event({{"event", "control.error"},
                                                    {"message", "unknown command"}});
                            }
                        });
                        if (command.at("command") == "node.shutdown") break;
                    } catch (const std::exception& error) {
                        emit_console_event({{"event", "control.error"}, {"message", error.what()}});
                    }
                    continue;
                }
                if (line == "/quit") break;
                if (line.empty() || line.size() > pqvpn::strangenet::kMaxMessageBytes) continue;
                const auto timestamp = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                asio::post(io, [node, strange, text = line, timestamp] {
                    if (strange->room.empty()) {
                        std::cerr << "StrangeNet send deferred: no room joined\n";
                        return;
                    }
                    const auto monotonic_ms = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count());
                    const auto flood = strange->outbound_flood.accept(
                        {strange->room, "local", 1, timestamp, text}, monotonic_ms);
                    if (!flood.allowed) {
                        std::cerr << "StrangeNet send deferred: antiflood limit; retry in "
                                  << flood.retry_after_ms << " ms\n";
                        return;
                    }
                    auto& sequence = strange->sequences[strange->room];
                    const auto current = ++sequence;
                    const std::size_t recipients = strange->peer
                        ? (node->send_strangenet_message(
                               *strange->peer, strange->room, current, timestamp, text) ? 1u : 0u)
                        : node->broadcast_strangenet_message(
                               strange->room, current, timestamp, text);
                    if (recipients == 0)
                        std::cerr << "StrangeNet send deferred: authenticated peer session is unavailable\n";
                    else
                        std::cout << "StrangeNet message accepted for " << recipients
                                  << " authenticated peer(s)\n";
                });
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
                std::cerr << "PQVPN Tunnel has no IPv4 address; refusing to run without "
                             "a leak-safe default route\n";
                listener.stop();
                return 1;
            } else {
                    // The tunnel default route would also capture this node's own UDP
                // transport: peer datagrams would enter the adapter, get
                // re-encrypted by the data path, and loop. Before it can win,
                // pin every known tunnel peer (and control-plane destination)
                // to the pre-VPN physical gateway with /32 host routes.
                const auto physical = pqvpn::platform::find_default_route(adapter_route->interface_index);
                if (!physical) {
                    std::cerr << "no pre-VPN default route found; refusing to run because peer "
                                 "exclusions cannot be installed safely\n";
                    listener.stop();
                    return 1;
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
                        // Incomplete exclusions mean we cannot install the full
                        // tunnel safely. Continuing would leave the host running
                        // with the physical network exposed, so fail closed.
                        const auto cleanup = peer_routes.remove_all();
                        if (!cleanup.complete) {
                            std::cerr << "peer route cleanup incomplete: " << cleanup.error << "\n";
                        }
                        node->set_peer_route_hook(nullptr);
                        std::cerr
                            << "peer route exclusions incomplete; refusing to run without VPN routes\n";
                        listener.stop();
                        return 1;
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
                            emit_console_event({{"event", "tunnel.ready"},
                                                {"ipv4", "full"},
                                                {"ipv6", full_tunnel_v6 ? "full" : "blocked"},
                                                {"fail_closed", true}});
                        } else {
                            // The full-tunnel default could not be established.
                            // Continuing would leak traffic on the physical
                            // network, so fail closed.
                            const auto cleanup = peer_routes.remove_all();
                            if (!cleanup.complete) {
                                std::cerr << "peer route cleanup incomplete: " << cleanup.error << "\n";
                            }
                            node->set_peer_route_hook(nullptr);
                            std::cerr << "route installation failed (" << report.error
                                << "); refusing to continue without VPN routes\n";
                            listener.stop();
                            return 1;
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
    *shutdown = [&] {
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
#ifdef __linux__
        if (adapter) adapter->close();
        if (linux_network_active &&
            !run_linux_network_manager("down", config->tunnel.interface_name,
                                       config->tunnel.exit_host, config->tunnel.exit_port)) {
            std::cerr << "warning: killswitch cleanup incomplete; traffic remains blocked\n";
        }
        linux_network_active = false;
#endif
        node->stop_traffic_shaping();
        node->transport = nullptr;
        listener.stop();
        if (adapter) adapter->close(); // idempotent per OS
        io.stop();
    };
    signals.async_wait([shutdown](const asio::error_code& error, int) {
        if (!error) (*shutdown)();
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
