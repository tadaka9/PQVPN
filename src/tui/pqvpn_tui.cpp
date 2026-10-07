#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>

#include "config_module.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {

struct Options {
    std::string config = "config.json";
    std::string node;
    bool smoke_test = false;
};

const char* os_name() {
#if defined(_WIN32)
    return "Windows 10+";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#else
    return "Unknown OS";
#endif
}

const char* tunnel_name() {
#if defined(_WIN32)
    return "PQVPN native NDIS tunnel";
#elif defined(__APPLE__)
    return "Network Extension boundary";
#elif defined(__linux__)
    return "/dev/net/tun";
#else
    return "No native tunnel adapter";
#endif
}

std::string default_node(const char* argv0) {
    const auto directory = std::filesystem::absolute(argv0).parent_path();
#if defined(_WIN32)
    return (directory / "pqvpn_node.exe").string();
#else
    return (directory / "pqvpn_node").string();
#endif
}

std::string shell_quote(const std::string& value) {
#if defined(_WIN32)
    std::string quoted = "\"";
    for (const char character : value) quoted += character == '"' ? "\\\"" : std::string(1, character);
    return quoted + "\"";
#else
    std::string quoted = "'";
    for (const char character : value) quoted += character == '\'' ? "'\\''" : std::string(1, character);
    return quoted + "'";
#endif
}

void clear_screen() {
    std::cout << "\033[2J\033[H";
}

void initialize_terminal() {
#if defined(_WIN32)
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode)) {
        SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif
}

void render(const pqvpn::config::Config& config, const std::string& path) {
    clear_screen();
    std::cout << "\033[1;36mPQVPN CONTROL DECK\033[0m  C++23 terminal console\n"
              << "────────────────────────────────────────────────────────\n"
              << "OS              " << os_name() << "\n"
              << "Tunnel          " << tunnel_name() << "\n"
              << "Configuration   " << path << "\n"
              << "Listen          " << config.network.bind_address << ':' << config.network.port << "\n"
              << "Verification    " << (config.security.strict_sig_verify ? "strict" : "relaxed") << "\n"
              << "Adaptive PQTP   " << (config.adaptive_transport.enabled ? "enabled" : "disabled")
              << " · " << pqvpn::transport::to_string(config.adaptive_transport.mode) << "\n"
              << "Traffic shaping " << (config.traffic_shaping.enabled ? "enabled" : "disabled") << "\n"
              << "External path   " << (config.external_transport ? config.external_transport->engine : "direct") << "\n"
              << "Bootstrap peers " << config.bootstrap.size() << "\n"
              << "────────────────────────────────────────────────────────\n"
              << "[1] Refresh and validate   [2] Start node\n"
              << "[3] Show platform details  [4] StrangeNet utility\n"
              << "[q] Quit\n> " << std::flush;
}

int run_node(const Options& options) {
    const std::string command = shell_quote(options.node) + " --config " + shell_quote(options.config);
    clear_screen();
    std::cout << "Starting pqvpn_node. Return here when it stops.\n\n";
    return std::system(command.c_str());
}

bool parse(int argc, char** argv, Options& options) {
    options.node = default_node(argv[0]);
    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        if (arg == "--smoke-test") options.smoke_test = true;
        else if ((arg == "--config" || arg == "-c") && index + 1 < argc) options.config = argv[++index];
        else if (arg == "--node" && index + 1 < argc) options.node = argv[++index];
        else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: pqvpn_tui [--config PATH] [--node PATH] [--smoke-test]\n";
            return false;
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << '\n';
            return false;
        }
    }
    return !options.node.empty() && !options.config.empty();
}

} // namespace

int main(int argc, char** argv) {
    initialize_terminal();
    Options options;
    if (!parse(argc, argv, options)) return argc > 1 ? 2 : 0;
    auto loaded = pqvpn::config::load_config(options.config);
    if (!loaded) {
        std::cerr << "Cannot load a valid configuration: " << options.config << '\n';
        return 1;
    }
    if (options.smoke_test) {
        std::cout << "PQVPN TUI ready on " << os_name() << " using " << tunnel_name() << '\n';
        return 0;
    }

    for (;;) {
        render(*loaded, options.config);
        std::string choice;
        if (!std::getline(std::cin, choice) || choice == "q" || choice == "Q") break;
        if (choice == "1") {
            loaded = pqvpn::config::load_config(options.config);
            if (!loaded) {
                std::cerr << "Configuration validation failed. Press Enter to retry.";
                std::getline(std::cin, choice);
                return 1;
            }
        } else if (choice == "2") {
            run_node(options);
            loaded = pqvpn::config::load_config(options.config);
        } else if (choice == "3") {
            clear_screen();
            std::cout << "Operating system: " << os_name() << "\nTunnel integration: " << tunnel_name()
                      << "\nPQTP policy: UDP preferred with measured TCP fallback\n\nPress Enter to return.";
            std::getline(std::cin, choice);
        } else if (choice == "4") {
            clear_screen();
            std::cout << "StrangeNet\n──────────\nAuthenticated peer rooms use bounded 2 KiB frames and per-sender replay counters.\nStart a room with pqvpn_node --strangenet-room NAME --strangenet-peer 64_HEX_DIGITS.\nOnly an established PQVPN session can carry messages; /quit leaves the console.\n\nPress Enter to return.";
            std::getline(std::cin, choice);
        }
    }
    return 0;
}
