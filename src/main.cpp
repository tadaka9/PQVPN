#include <asio.hpp>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <string>

#ifdef _WIN32
#include "platform/windows_routes.hpp"
#include "platform/windows_tap.hpp"
#include "routing/peer_route_manager.hpp"
#endif

#include "routing/route_transaction.hpp"

#include "config_module.hpp"
#include "logging_module.hpp"
#include "metrics_module.hpp"
#include "network_module.hpp"
#include "node_module.hpp"
#include "serialization_module.hpp"

namespace {

struct CliArgs {
    std::string config_path = "config.json";
    std::string log_level = "info";
    bool smoke_test = false;
    bool help = false;
#ifdef _WIN32
    bool no_tap = false;
    std::string tap_guid;
#endif
};

void print_usage(const char* program) {
    std::cout
        << "Usage: " << program << " [--config PATH] [--log-level LEVEL] [--smoke-test]\n\n"
        << "Default mode starts the PQVPN node runtime and remains active until Ctrl+C/SIGTERM.\n"
        << "  -c, --config PATH       Configuration file path (default: config.json)\n"
        << "      --log-level LEVEL   spdlog level hint (default: info)\n"
        << "      --smoke-test        Load/serialize config and exit\n"
#ifdef _WIN32
        << "      --tap-guid GUID     Use this TAP-Windows adapter (default: auto-detect)\n"
        << "      --no-tap            Run without a TAP-Windows adapter\n"
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
#ifdef _WIN32
        } else if (value == "--no-tap") {
            args.no_tap = true;
        } else if (value == "--tap-guid") {
            if (++index >= argc) {
                std::cerr << value << " requires an adapter GUID\n";
                return std::nullopt;
            }
            args.tap_guid = argv[index];
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
    return args;
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
    // Establish this node's stable identity before it can relay or deliver
    // locally: handle_relay binds its AAD to peer_hash8(my_id) and requires it.
    // When no ed25519 key is loaded the node cannot peel onions — say so
    // explicitly instead of silently rejecting every relay (see establish_identity).
    if (!node->establish_identity()) {
        std::cerr << "warning: no node identity established (no ed25519 key); "
                  << "onion relay and local delivery will be rejected\n";
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

#ifdef _WIN32
    std::unique_ptr<pqvpn::platform::WindowsTap> tap;
    pqvpn::routing::RouteTransaction route_plan;
    pqvpn::platform::WindowsRouteBackend route_backend;
    // Declared with the other route state (not inside the TAP block) so the
    // signal handler can roll back peer exclusions on shutdown. Safe to leave
    // unused when no_tap is set: remove_all() on an empty manager succeeds.
    pqvpn::routing::PeerRouteManager peer_routes(route_backend);
    if (!args.no_tap) {
        try {
            tap = std::make_unique<pqvpn::platform::WindowsTap>();
            tap->open(args.tap_guid, [node](std::vector<uint8_t> frame) {
                // Adapter -> tunnel: forward to the selected established session.
                asio::co_spawn(node->get_io_context(),
                    node->forward_adapter_packet(std::move(frame)), asio::detached);
            });
            node->set_tunnel_packet_handler([tap = tap.get()](std::vector<uint8_t> frame) {
                // Tunnel -> adapter. The adapter may already be closed during
                // shutdown; drop the frame instead of unwinding the coroutine.
                try {
                    tap->write(frame);
                } catch (const std::exception&) {
                }
            });
            std::cout << "TAP-Windows adapter active: " << tap->guid() << "\n";

            // Route traffic through the adapter only when it actually has an
            // IPv4 address; otherwise a default route would blackhole. The row
            // is the Windows default route: destination 0.0.0.0 with a zero
            // mask (prefix length 0, matching every destination) and the
            // adapter address as next hop. A /32 here would match only the
            // literal 0.0.0.0 address and send no real traffic to the TAP.
            const auto adapter_route = pqvpn::platform::find_adapter_ipv4(tap->guid());
            if (!adapter_route) {
                std::cerr << "TAP-Windows adapter has no IPv4 address; skipping route installation\n";
            } else {
                // The TAP default route would also capture this node's own UDP
                // transport: peer datagrams would enter the adapter, get
                // re-encrypted by the data path, and loop. Before it can win,
                // pin every known tunnel peer (and control-plane destination)
                // to the pre-VPN physical gateway with /32 host routes.
                const auto physical = pqvpn::platform::find_default_route(adapter_route->interface_index);
                if (!physical) {
                    std::cerr << "no pre-VPN default route found; skipping TAP default route "
                              << "(installing it without peer exclusions would loop tunnel traffic)\n";
                } else {
                    peer_routes.set_physical_gateway(
                        {physical->ipv4, physical->interface_index});

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
                        std::cerr << "peer route exclusions incomplete; skipping TAP default route\n";
                    } else {
                        route_plan.add(pqvpn::routing::RouteEntry{
                            asio::ip::make_address_v4("0.0.0.0"), 0,
                            adapter_route->ipv4, adapter_route->interface_index});

                        if (const auto report = route_plan.commit(route_backend); report.committed) {
                            std::cout << "default route installed through the TAP-Windows adapter\n";
                        } else {
                            // The default is down; drop the exclusions we just
                            // created so no owned routes survive a failed setup.
                            const auto cleanup = peer_routes.remove_all();
                            (void)cleanup;
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
            std::cerr << "TAP initialization failed: " << error.what() << "\n";
            listener.stop();
            return 1;
        }
    }
#endif

    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](const asio::error_code&, int) {
#ifdef _WIN32
        if (tap) {
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
            tap->close();
        }
#endif
        node->transport = nullptr;
        listener.stop();
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
