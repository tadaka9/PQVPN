#pragma once

#include <chrono>
#include <cerrno>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <thread>
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
        if (backend == Backend::OpenVPN3) {
            return {"openvpn3", "session-start", "--config", config.string()};
        }
        throw std::invalid_argument("native backend has no external process");
    }
    std::vector<std::string> stop_argv() const {
        if (backend == Backend::WireGuard) return {"wg-quick", "down", config.string()};
        if (backend == Backend::OpenVPN3)
            return {"openvpn3", "session-manage", "--config", config.string(), "--disconnect"};
        return {};
    }
    bool persistent() const { return false; }
};

class ExternalTunnelProcess {
public:
    explicit ExternalTunnelProcess(ExternalProcessSpec spec) : spec_(std::move(spec)) {}
    ExternalTunnelProcess(const ExternalTunnelProcess&) = delete;
    ExternalTunnelProcess& operator=(const ExternalTunnelProcess&) = delete;
    ~ExternalTunnelProcess() { stop(); }

    bool running() {
        if (!spec_.persistent()) return active_;
#ifdef _WIN32
        if (!process_) return false;
        DWORD code = 0;
        if (GetExitCodeProcess(process_, &code) && code == STILL_ACTIVE) return true;
        CloseHandle(process_); process_ = nullptr; active_ = false; return false;
#else
        if (pid_ <= 0) return false;
        const auto result = waitpid(pid_, nullptr, WNOHANG);
        if (result == 0) return true;
        if (result == pid_) { pid_ = -1; active_ = false; }
        return false;
#endif
    }

    void start() {
        if (running()) return;
        const auto args = spec_.argv();
        if (!spec_.persistent()) {
            if (run_one_shot(args) != 0) throw std::runtime_error("inner tunnel setup failed");
            active_ = true;
            return;
        }
#ifdef _WIN32
        auto command = windows_command(args);
        STARTUPINFOA si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &si, &pi)) throw std::runtime_error("cannot start external tunnel plugin");
        CloseHandle(pi.hThread); process_ = pi.hProcess;
        if (WaitForSingleObject(process_, 500) == WAIT_OBJECT_0) {
            CloseHandle(process_); process_ = nullptr;
            throw std::runtime_error("openvpn exited during startup");
        }
        active_ = true;
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
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        int status = 0;
        if (waitpid(pid_, &status, WNOHANG) == pid_) {
            pid_ = -1;
            throw std::runtime_error("openvpn exited during startup");
        }
        active_ = true;
#endif
    }

    void stop() noexcept {
        if (!active_) return;
        if (!spec_.persistent()) {
            try { (void)run_one_shot(spec_.stop_argv()); } catch (...) {}
            active_ = false;
            return;
        }
#ifdef _WIN32
        if (process_) { TerminateProcess(process_, 0); CloseHandle(process_); process_ = nullptr; }
#else
        if (pid_ > 0) {
            kill(pid_, SIGTERM);
            bool exited=false;
            for (int attempt=0; attempt<20; ++attempt) {
                if (waitpid(pid_, nullptr, WNOHANG)==pid_) { exited=true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (!exited) { kill(pid_, SIGKILL); waitpid(pid_, nullptr, 0); }
            pid_ = -1;
        }
#endif
        active_ = false;
    }

private:
    static int run_one_shot(const std::vector<std::string>& args) {
        if (args.empty()) return -1;
#ifdef _WIN32
        auto command = windows_command(args);
        STARTUPINFOA si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                            nullptr, nullptr, &si, &pi)) return -1;
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code); CloseHandle(pi.hProcess);
        return static_cast<int>(code);
#else
        const pid_t child = fork();
        if (child < 0) return -1;
        if (child == 0) {
            std::vector<char*> argv;
            for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
            argv.push_back(nullptr); execvp(argv.front(), argv.data()); _exit(127);
        }
        int status = 0;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
    }
#ifdef _WIN32
    static std::string windows_command(const std::vector<std::string>& args) {
        std::string command;
        for (const auto& arg : args) { if (!command.empty()) command += ' '; command += '"' + arg + '"'; }
        return command;
    }
#endif
    ExternalProcessSpec spec_;
    bool active_ = false;
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
    std::error_code error;
    if (!std::filesystem::is_regular_file(spec.config, error) || error)
        throw std::invalid_argument("external plugin configuration must be an existing regular file");
    return spec;
}

} // namespace pqvpn::tunnel
