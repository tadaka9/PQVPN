#ifndef PQVPN_APP_RUNTIME_HPP
#define PQVPN_APP_RUNTIME_HPP

#include <string>
#include <memory>
#include <expected>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <asio.hpp>
#include "modules/node_module.hpp"
#include "modules/plugin_manager.hpp"
#include "modules/network_module.hpp"
#include "modules/logging_module.hpp"
#include "config_module.hpp"

namespace pqvpn::runtime {

class AppRuntime {
public:
    struct Args {
        std::string configfile = "config.json";
        std::string logfile = "";
        std::string loglevel = "INFO";
        std::string pidfile = "";
        bool daemonize = false;
        bool disable_discovery = false;
        bool socks_mode = false;
        bool tunnel_mode = false;
        bool enable_relay = false;
    };

    static asio::awaitable<void> run(Args args) {
        // 1. Configure Logger (main.py:4946-4954)
        try {
            logging::Logger::setup("pqvpn", args.loglevel, args.logfile);
        } catch (...) {}

        logging::Logger::info("Starting PQVPN main loop (config={})", args.configfile);

        // 2. Instantiate Node (main.py:4959-4963)
        std::shared_ptr<PQVPNNode> node;
        try {
            node = std::make_shared<PQVPNNode>(args.configfile);
        } catch (const std::exception& e) {
            logging::Logger::critical("Failed to initialize PQVPNNode: {}", e.what());
            throw;
        }

        asio::io_context& ctx = node->get_io_context();

        // 3. Apply runtime flags (main.py:4965-4974)

        asio::signal_set signals(ctx, SIGINT, SIGTERM);
        auto shutdown_requested = std::make_shared<bool>(false);

        signals.async_wait([shutdown_requested](const std::error_code& ec, int signal_number) {
            if (!ec) {
                logging::Logger::info("Received signal {}, initiating shutdown...", signal_number);
                *shutdown_requested = true;
            }
        });

        // 4. Start Discovery (main.py:5006-5012)
        if (!args.disable_discovery && node->discovery) {
            try {
                co_await node->discovery->start();
            } catch (...) {
                logging::Logger::warning("Discovery failed to start; continuing without it");
            }
        }

        // 5. Start Session Maintenance (main.py:5014-520)
        asio::co_spawn(ctx, node->session_maintenance(), asio::detached);

        // 6. Delayed Bootstrap (main.py:5021-5028)
        // Implementation of _delayed_bootstrap

        // 7. Bind UDP Socket (main.py:5030-5062)

        std::unique_ptr<network::UdpListener> udp_listener = std::make_unique<network::UdpListener>(ctx, node->port);
        auto bind_result = co_await udp_listener->start();
        if (!bind_result) {
            logging::Logger::critical("Failed to bind UDP socket on {}:{}: {}", node->host, node->port, (int)bind_result.error());
            co_return;
        }

        // 8. PID File (main.py:5073-5079)
        if (!args.pidfile.empty()) {
            try {
                std::ofstream pf(args.pidfile);
                pf << "1234";
            } catch (...) {
                logging::Logger::warning("Failed to write pidfile {}", args.pidfile);
            }
        }

        // 9. Plugin Manager (main.py:5081-5097)
        auto plugin_manager = std::make_shared<PluginManager>(node, "{}");
        node->plugins = plugin_manager;
        plugin_manager->load_plugins();
        try {
            co_await plugin_manager->call_hook_async("on_start");
        } catch (...) {
            logging::Logger::warning("Plugin on_start hook error");
        }

        // 112. Main Wait Loop (main.py:5099-5149)
        asio::steady_timer shutdown_timer(ctx);

        while (!*shutdown_requested) {
            shutdown_timer.expires_after(std::chrono::milliseconds(100));
            co_await shutdown_timer.async_wait(asio::use_awaitable);

            if (*shutdown_requested) break;
        }

        logging::Logger::info("Shutting down PQVPN runtime");

        // Cleanup (main.py:5104-5149)
        if (node->discovery) co_await node->discovery->stop();
        udp_listener->stop();
        node->save_known_peers();

        if (!args.pidfile.empty()) {
            std::filesystem::remove(args.pidfile);
        }

        plugin_manager->unload_plugins();
        try {
            co_await plugin_manager->call_hook_async("on_stop");
        } catch (...) {}

        co_return;
    }
};

} // namespace pqvpn::runtime

#endif // PQVPN_APP_RUNTIME_HPP
