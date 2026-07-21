#include <asio.hpp>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <string>

#ifdef _WIN32
#include "platform/windows_tap.hpp"
#endif

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
    if (!args.no_tap) {
        try {
            tap = std::make_unique<pqvpn::platform::WindowsTap>();
            tap->open(args.tap_guid, [](std::vector<uint8_t>) {
                // Frames are accepted once peer routing selects a negotiated session.
            });
            std::cout << "TAP-Windows adapter active: " << tap->guid() << "\n";
        } catch (const std::exception& error) {
            std::cerr << "TAP initialization failed: " << error.what() << "\n";
            listener.stop();
            return 1;
        }
    }
#endif

    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](const asio::error_code&, int) {
#ifdef _WIN32
        if (tap) tap->close();
#endif
        node->transport = nullptr;
        listener.stop();
        io.stop();
    });

    std::cout << "PQVPN Node Runtime started with config: " << args.config_path << "\n";
    io.run();
    std::cout << "PQVPN Node Runtime stopped.\n";

    return 0;
}
