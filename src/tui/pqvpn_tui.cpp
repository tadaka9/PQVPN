// PQVPN TUI — a real-time, full-screen terminal console.
//
// Pairs a live dashboard with the PQVPN node: it spawns pqvpn_node with its
// stdout/stderr captured on a pipe, renders a resize-aware ANSI screen, and
// lets the operator start/stop the node, clear the log, and quit while the
// node output scrolls by live. Everything is self-contained (C++23 standard
// library + raw console APIs on Windows) so it stays a dumb terminal client.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "config_module.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
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
    return "Unknown";
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

/* ---------------- terminal helpers ---------------- */

struct ScreenSize {
    int cols = 100;
    int rows = 30;
};

ScreenSize current_size() {
#if defined(_WIN32)
    ScreenSize size;
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (output != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(output, &info)) {
        size.cols = static_cast<int>(info.srWindow.Right - info.srWindow.Left + 1);
        size.rows = static_cast<int>(info.srWindow.Bottom - info.srWindow.Top + 1);
    }
    if (size.cols < 40) size.cols = 40;
    if (size.rows < 12) size.rows = 12;
    return size;
#else
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        return {static_cast<int>(ws.ws_col), static_cast<int>(ws.ws_row)};
    }
    return {};
#endif
}

void hide_cursor() { std::cout << "\033[?25l"; }
void show_cursor() { std::cout << "\033[?25h"; }
void home() { std::cout << "\033[H"; }
void set_raw(bool raw);
bool is_raw = false;

#if defined(_WIN32)
void enable_vt() {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode)) {
        SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}
#else
struct termios saved_termios;
#endif

void set_raw(const bool raw) {
#ifdef _WIN32
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (input == INVALID_HANDLE_VALUE || !GetConsoleMode(input, &mode)) return;
    if (raw) {
        mode &= ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
        SetConsoleMode(input, mode);
    } else {
        SetConsoleMode(input, mode);
    }
    is_raw = raw;
#else
    termios t{};
    static bool restored = false;
    if (raw && !is_raw) {
        if (tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
            t = saved_termios;
            t.c_lflag &= ~(ICANON | ECHO | ISIG);
            t.c_cc[VMIN] = 1;
            t.c_cc[VTIME] = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &t);
            is_raw = true;
            restored = false;
        }
    } else if (!raw && is_raw) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
        is_raw = false;
        restored = true;
    }
#endif
}

/* Non-blocking single-key capture. Returns -1 when no key is pending. */
int poll_key() {
#if defined(_WIN32)
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    INPUT_RECORD record{};
    DWORD count = 0;
    if (WaitForSingleObject(input, 0) == WAIT_OBJECT_0 &&
        ReadConsoleInputW(input, &record, 1, &count) && count == 1 &&
        record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown) {
        const wchar_t c = record.Event.KeyEvent.uChar.UnicodeChar;
        return c != 0 ? static_cast<int>(c) : -1;
    }
    return -1;
#else
    pollfd fd{STDIN_FILENO, POLLIN, 0};
    if (poll(&fd, 1, 0) <= 0) return -1;
    unsigned char byte = 0;
    const ssize_t n = ::read(STDIN_FILENO, &byte, 1);
    if (n <= 0) return -1;
    return static_cast<int>(byte);
#endif
}

/* ---------------- node child process ---------------- */

class NodeProcess {
public:
    ~NodeProcess() { stop(); join_reader(); }

    bool running() const { return running_.load(); }
    bool finished() const { return finished_.load(); }
    long exit_code() const { return exit_code_.load(); }

    bool start(const std::string& executable, const std::vector<std::string>& args) {
        stop();
        join_reader();
        {
            std::lock_guard<std::mutex> guard(buffer_mutex_);
            scrollback_.clear();
        }
        finished_.store(false);
        exit_code_.store(0);
        running_.store(true);
#ifndef _WIN32
        child_pid_.store(0);
#else
        child_handle_ = nullptr;
#endif

        std::string command = executable;
        for (const auto& arg : args) command += " \"" + arg + "\"";

#ifdef _WIN32
        SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        HANDLE read_pipe = nullptr, write_pipe = nullptr;
        if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) { running_.store(false); return false; }
        SetHandleInformation(write_pipe, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = si.hStdError = write_pipe;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        PROCESS_INFORMATION pi{};
        const int wide = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
        std::wstring wcommand(static_cast<std::size_t>(wide), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, wcommand.data(), wide);
        if (!CreateProcessW(nullptr, wcommand.data(), nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(read_pipe); CloseHandle(write_pipe);
            running_.store(false);
            return false;
        }
        CloseHandle(write_pipe);
        CloseHandle(pi.hThread);
        child_handle_ = pi.hProcess;
        reader_ = std::thread([this, read_pipe, handle = pi.hProcess] {
            std::vector<char> buffer(4096);
            DWORD read = 0;
            for (;;) {
                if (!ReadFile(read_pipe, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &read, nullptr)) {
                    break;
                }
                if (read > 0) append(buffer.data(), static_cast<std::size_t>(read));
            }
            CloseHandle(read_pipe);
            WaitForSingleObject(handle, INFINITE);
            DWORD code = 0;
            GetExitCodeProcess(handle, &code);
            CloseHandle(handle);
            exit_code_.store(static_cast<long>(static_cast<int>(code)));
            finished_.store(true);
            running_.store(false);
        });
#else
        int fds[2];
        if (pipe(fds) != 0) { running_.store(false); return false; }
        const pid_t pid = fork();
        if (pid < 0) { close(fds[0]); close(fds[1]); running_.store(false); return false; }
        if (pid == 0) {
            dup2(fds[1], STDOUT_FILENO);
            dup2(fds[1], STDERR_FILENO);
            close(fds[0]); close(fds[1]);
            execl("/bin/sh", "sh", "-c", command.c_str(), static_cast<char*>(nullptr));
            _exit(127);
        }
        close(fds[1]);
        child_pid_.store(pid);
        reader_ = std::thread([this, fd = fds[0], pid] {
            std::vector<char> buffer(4096);
            for (;;) {
                const ssize_t n = ::read(fd, buffer.data(), buffer.size());
                if (n <= 0) break;
                append(buffer.data(), static_cast<std::size_t>(n));
            }
            ::close(fd);
            int status = 0;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) exit_code_.store(WEXITSTATUS(status));
            else exit_code_.store(128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0));
            finished_.store(true);
            running_.store(false);
        });
#endif
        // start() set running_ on entry and reset it on every early failure, so
        // reflecting the flag avoids a hard-coded success return here.
        return running_.load();
    }

    void stop() {
        if (!running_.load()) return;
#ifdef _WIN32
        HANDLE handle = child_handle_;
        if (handle != nullptr) {
            TerminateProcess(handle, 0);
        }
#else
        const pid_t pid = child_pid_.load();
        if (pid > 1) ::kill(pid, SIGTERM);
#endif
    }

    std::vector<std::string> tail(const std::size_t count) const {
        std::lock_guard<std::mutex> guard(buffer_mutex_);
        std::vector<std::string> result;
        result.reserve(std::min(count, scrollback_.size()));
        const std::size_t begin =
            scrollback_.size() > count ? scrollback_.size() - count : 0;
        for (std::size_t i = begin; i < scrollback_.size(); ++i) result.push_back(scrollback_[i]);
        return result;
    }

    void clear_log() {
        std::lock_guard<std::mutex> guard(buffer_mutex_);
        scrollback_.clear();
    }

private:
    void append(const char* data, const std::size_t length) {
        std::lock_guard<std::mutex> guard(buffer_mutex_);
        constexpr std::size_t kMaxLines = 2000;
        scrollback_.push_back(std::string(data, length));
        if (scrollback_.size() > kMaxLines) {
            scrollback_.erase(scrollback_.begin(),
                              scrollback_.begin() + static_cast<std::int64_t>(scrollback_.size()) - kMaxLines);
        }
    }

    void join_reader() {
        if (reader_.joinable()) reader_.join();
    }

    std::atomic<bool> running_{false};
    std::atomic<bool> finished_{false};
    std::atomic<long> exit_code_{0};
#ifndef _WIN32
    std::atomic<pid_t> child_pid_{0};
#else
    HANDLE child_handle_ = nullptr;
#endif
    mutable std::mutex buffer_mutex_;
    std::vector<std::string> scrollback_;
    std::thread reader_;
};

/* ---------------- rendering ---------------- */

void render(const ScreenSize& size, const pqvpn::config::Config& config,
            const std::string& path, const std::string& executable,
            const NodeProcess& node, const std::string& notice) {
    home();
    const int pad = 1;
    auto row = [&](const std::string& s) {
        const int available = std::max(0, size.cols - pad);
        const std::string clipped = s.substr(0, static_cast<std::size_t>(available));
        std::cout << (pad ? " " : "") << clipped << "\033[K\n";
    };
    auto rule = [&]() { row(std::string(static_cast<std::size_t>(std::max(0, size.cols - 0)), '-')); };

    row("\033[1;36mPQVPN\033[0m \033[2mPRIVACY CONSOLE\033[0m  ·  live node monitor");
    rule();

    const std::string state = node.finished() ? "stopped · exit " + std::to_string(node.exit_code())
                             : node.running() ? "running"
                                              : "idle";
    std::string status = "state    \033["
                         + std::string(node.running() && !node.finished() ? "32m●" : "31m○")
                         + "\033[0m " + state;
    row(status);
    row("os       " + std::string(os_name()));
    row("tunnel   " + std::string(tunnel_name()));
    row("config   " + path);
    row("node     " + executable);
    row("listen   " + config.network.bind_address + ":" + std::to_string(config.network.port));
    row("verify   " + std::string(config.security.strict_sig_verify ? "strict" : "relaxed"));
    row("adaptive " + std::string(config.adaptive_transport.enabled ? "enabled" : "disabled")
        + " · " + pqvpn::transport::to_string(config.adaptive_transport.mode));
    row("shaping  " + std::string(config.traffic_shaping.enabled ? "enabled" : "disabled"));
    if (!notice.empty()) row("\033[33m" + notice + "\033[0m");
    rule();

    // Live log area.
    const std::vector<std::string> lines = node.tail(static_cast<std::size_t>(std::max(0, size.rows - 22)));
    for (const auto& line : lines) row(line);
    for (int i = static_cast<int>(lines.size()); i < std::max(0, size.rows - 22); ++i) {
        std::cout << "\033[K\n";
    }

    rule();
    row("\033[90m[d] start   [x] stop   [c] clear   [r] refresh   [q] quit\033[0m");
    std::cout << std::flush;
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
#if defined(_WIN32)
    enable_vt();
#else
    setvbuf(stdout, nullptr, _IONBF, 0);
#endif
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

    NodeProcess node;
    hide_cursor();
    set_raw(true);

    const auto cleanup = [&]() {
        set_raw(false);
        show_cursor();
        std::cout << "\033[2J\033[H" << std::flush;
    };

    std::string notice;
    bool quit = false;
    while (!quit) {
        const ScreenSize size = current_size();
        render(size, *loaded, options.config, options.node, node, notice);

        // Small pause so the terminal can breathe and keys register.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(140);
        while (std::chrono::steady_clock::now() < deadline) {
            const int key = poll_key();
            if (key >= 0) {
                const char c = static_cast<char>(key);
                if (c == 'q' || c == 'Q') { quit = true; break; }
                else if (c == 'c' || c == 'C') { node.clear_log(); notice.clear(); }
                else if (c == 'r' || c == 'R') { notice.clear(); }
                else if (c == 'd' || c == 'D') {
                    if (node.running() && !node.finished()) {
                        notice = "node already running";
                    } else {
                        if (node.start(options.node,
                                       {"--config", options.config})) {
                            notice = "node starting…";
                        } else {
                            notice = "failed to start node";
                        }
                    }
                }
                else if (c == 'x' || c == 'X') {
                    node.stop();
                    notice = "stop requested";
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    node.stop();
    cleanup();
    return 0;
}
