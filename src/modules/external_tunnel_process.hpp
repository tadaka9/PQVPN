#pragma once

#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#include "tunnel_plugin.hpp"
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace pqvpn::tunnel {

// Fixed executable mapping shared by all frontends. The supervisor must pass
// argv directly to the OS process API; it must never invoke a shell.
struct ExternalProcessSpec {
    Backend backend = Backend::Native;
    std::filesystem::path config;
    std::chrono::milliseconds startup_timeout{10000};

    std::vector<std::string> argv() const {
        if (backend == Backend::WireGuard) {
            return {"wg-quick", "up", config.string()};
        }
        if (backend == Backend::OpenVPN) {
            return {"openvpn", "--config", config.string()};
        }
        throw std::invalid_argument("native backend has no external process");
    }
};

class ExternalTunnelProcess {
public:
    explicit ExternalTunnelProcess(ExternalProcessSpec spec) : spec_(std::move(spec)) {}
    ExternalTunnelProcess(const ExternalTunnelProcess&) = delete;
    ExternalTunnelProcess& operator=(const ExternalTunnelProcess&) = delete;
    ~ExternalTunnelProcess() { stop(); }

    bool running() const {
#ifdef _WIN32
        if (!process_) return false;
        DWORD code = 0;
        return GetExitCodeProcess(process_, &code) && code == STILL_ACTIVE;
#else
        if (pid_ <= 0) return false;
        const auto result = waitpid(pid_, nullptr, WNOHANG);
        return result == 0;
#endif
    }

    void start() {
        if (running()) throw std::runtime_error("external tunnel plugin is already running");
        const auto args = spec_.argv();
#ifdef _WIN32
        std::string command;
        for (const auto& arg : args) { if (!command.empty()) command += ' '; command += '"' + arg + '"'; }
        STARTUPINFOA si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &si, &pi)) throw std::runtime_error("cannot start external tunnel plugin");
        CloseHandle(pi.hThread); process_ = pi.hProcess;
#else
        pid_ = fork();
        if (pid_ < 0) throw std::runtime_error("cannot fork external tunnel plugin");
        if (pid_ == 0) {
            std::vector<char*> argv;
            argv.reserve(args.size() + 1);
            for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
            argv.push_back(nullptr);
            execvp(argv.front(), argv.data());
            _exit(127);
        }
#endif
    }

    void stop() noexcept {
#ifdef _WIN32
        if (process_) { TerminateProcess(process_, 0); CloseHandle(process_); process_ = nullptr; }
#else
        if (pid_ > 0) { kill(pid_, SIGTERM); waitpid(pid_, nullptr, 0); pid_ = -1; }
#endif
    }

private:
    ExternalProcessSpec spec_;
#ifdef _WIN32
    HANDLE process_ = nullptr;
#else
    pid_t pid_ = -1;
#endif
};

inline ExternalProcessSpec make_external_process_spec(Backend backend,
                                                       const std::string& config) {
    ExternalProcessSpec spec{backend, validate_config_path(backend, config)};
    if (spec.config.empty()) {
        throw std::invalid_argument("external plugin configuration is required");
    }
    return spec;
}

} // namespace pqvpn::tunnel
