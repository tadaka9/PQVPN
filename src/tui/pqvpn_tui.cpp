// PQVPN TUI — a real-time, full-screen terminal console.
//
// Pairs a live dashboard with the PQVPN node: it spawns pqvpn_node with its
// stdout/stderr captured on a pipe, renders a resize-aware ANSI screen, and
// lets the operator start/stop the node, clear the log, and quit while the
// node output scrolls by live. Everything is self-contained (C++23 standard
// library + raw console APIs on Windows) so it stays a dumb terminal client.
#include <atomic>
#include <array>
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
#include "console/connection_state.hpp"
#include "console/event_state.hpp"
#include "console/default_profile.hpp"
#include "console/terminal_text.hpp"
#include "console/inner_tunnel_policy.hpp"

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
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#include <unistd.h>
#endif

namespace {

struct Options {
    std::string config;
    std::string node;
    bool smoke_test = false;
    bool no_tunnel = false;
    pqvpn::console::InnerTunnelOverride inner_tunnel;
    bool help = false;
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
    std::filesystem::path binary=std::filesystem::absolute(argv0);
    std::error_code error;
#if defined(__linux__)
    const auto actual=std::filesystem::read_symlink("/proc/self/exe",error);if(!error)binary=actual;
#elif defined(__APPLE__)
    std::array<char,4096> path{};uint32_t size=static_cast<uint32_t>(path.size());if(_NSGetExecutablePath(path.data(),&size)==0)binary=path.data();
#elif defined(_WIN32)
    std::array<wchar_t,32768> path{};const DWORD size=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));if(size>0&&size<path.size())binary=std::filesystem::path(path.data());
#endif
    const auto directory=binary.parent_path();
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
    size.cols=std::max(1,size.cols);size.rows=std::max(1,size.rows);
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
DWORD saved_input_mode=0;
void configure_utf8_console() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}
bool enable_vt() {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode)) {
        return SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
    }
    return false;
}
std::string tunnel_blocker() {
    const HANDLE driver=CreateFileW(L"\\\\.\\PQVPN_TUN0",GENERIC_READ|GENERIC_WRITE,
                                    FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,nullptr);
    if(driver!=INVALID_HANDLE_VALUE){CloseHandle(driver);return {};}
    const DWORD error=GetLastError();
    if(error==ERROR_ACCESS_DENIED)return "Tunnel driver access denied. Restart the console as administrator, then verify again.";
    if(error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND)
        return "PQVPN tunnel driver is not installed. This test build cannot protect system traffic; press M for relay mode.";
    return "PQVPN tunnel driver is unavailable (Windows error "+std::to_string(error)+"). Press M for relay mode.";
}
#else
struct termios saved_termios;
std::string tunnel_blocker() { return {}; }
#endif

void set_raw(const bool raw) {
#ifdef _WIN32
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (input == INVALID_HANDLE_VALUE || !GetConsoleMode(input, &mode)) return;
    if(raw&&!is_raw){saved_input_mode=mode;mode&=~(ENABLE_ECHO_INPUT|ENABLE_LINE_INPUT|ENABLE_PROCESSED_INPUT);SetConsoleMode(input,mode);}
    else if(!raw&&is_raw)SetConsoleMode(input,saved_input_mode);
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

    pqvpn::console::ConnectionSnapshot snapshot(bool relay_only) const {
        std::lock_guard<std::mutex> guard(buffer_mutex_);
        return {running()&&!finished(),events_.authenticated(),events_.tunnel_ready(),relay_only,stopping_.load(),finished()&&exit_code()!=0&&!stopping_.load()};
    }

    bool start(const std::string& executable, const std::vector<std::string>& args) {
        stop();
        join_reader();
        {
            std::lock_guard<std::mutex> guard(buffer_mutex_);
            scrollback_.clear();events_.reset();pending_output_.clear();
        }
        stopping_.store(false);
        finished_.store(false);
        exit_code_.store(0);
        running_.store(true);
#ifndef _WIN32
        child_pid_.store(0);
#else
        child_handle_ = nullptr;
#endif

#ifdef _WIN32
        auto quote=[](const std::string& value){std::string result="\"";std::size_t slashes=0;for(char c:value){if(c=='\\'){++slashes;continue;}if(c=='\"'){result.append(slashes*2+1,'\\');result+=c;}else{result.append(slashes,'\\');result+=c;}slashes=0;}result.append(slashes*2,'\\');return result+'\"';};
        std::string command=quote(executable);for(const auto& arg:args)command+=' '+quote(arg);
#endif

#ifdef _WIN32
        SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        HANDLE read_pipe = nullptr, write_pipe = nullptr;
        if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) { running_.store(false); return false; }
        SetHandleInformation(read_pipe,HANDLE_FLAG_INHERIT,0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = si.hStdError = write_pipe;
        const HANDLE null_input=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(null_input==INVALID_HANDLE_VALUE){CloseHandle(read_pipe);CloseHandle(write_pipe);running_.store(false);return false;}
        si.hStdInput=null_input;
        PROCESS_INFORMATION pi{};
        const int wide = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
        std::wstring wcommand(static_cast<std::size_t>(wide), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, wcommand.data(), wide);
        if (!CreateProcessW(nullptr, wcommand.data(), nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(null_input);CloseHandle(read_pipe); CloseHandle(write_pipe);
            running_.store(false);
            return false;
        }
        CloseHandle(null_input);CloseHandle(write_pipe);
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
            const int input=::open("/dev/null",O_RDONLY);if(input>=0){dup2(input,STDIN_FILENO);close(input);}
            std::vector<char*> argv;argv.push_back(const_cast<char*>(executable.c_str()));for(const auto& arg:args)argv.push_back(const_cast<char*>(arg.c_str()));argv.push_back(nullptr);
            execvp(executable.c_str(),argv.data());
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
        stopping_.store(true);
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
        pending_output_.append(data,length);
        constexpr std::size_t kMaxLine=16384,kMaxLines=2000;
        for(;;){const auto end=pending_output_.find('\n');if(end==std::string::npos)break;const auto line=pending_output_.substr(0,std::min(end,kMaxLine));pending_output_.erase(0,end+1);events_.accept_line(line);scrollback_.push_back(pqvpn::console::terminal_safe(line));}
        if(pending_output_.size()>kMaxLine){scrollback_.push_back("[Long node output truncated]");pending_output_.clear();}
        if(scrollback_.size()>kMaxLines)scrollback_.erase(scrollback_.begin(),scrollback_.end()-kMaxLines);
    }

    void join_reader() {
        if (reader_.joinable()) reader_.join();
#ifdef _WIN32
        if(child_handle_){CloseHandle(child_handle_);child_handle_=nullptr;}
#endif
    }

    std::atomic<bool> stopping_{false};
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
    std::string pending_output_;
    pqvpn::console::EventState events_;
    std::thread reader_;
};

/* ---------------- rendering ---------------- */

void render(const ScreenSize& size, const pqvpn::config::Config& config,
            const std::string& path, const std::string& executable,
            const NodeProcess& node, const std::string& notice, bool relay_only) {
    home();
    int emitted=0;
    auto row=[&](const std::string& value){if(emitted>=size.rows)return;std::cout<<"\033["<<emitted+1<<";1H "<<pqvpn::console::clip_ansi(value,std::max(0,size.cols-2))<<"\033[0m\033[K";++emitted;};
    auto rule=[&]{row(std::string(static_cast<std::size_t>(std::max(0,size.cols-2)),'-'));};
    const bool compact=size.cols<80||size.rows<24;
    const auto state=node.snapshot(relay_only);const auto phase=pqvpn::console::connection_phase(state);
    const std::string color=phase==pqvpn::console::ConnectionPhase::Protected||phase==pqvpn::console::ConnectionPhase::Relay?"32":phase==pqvpn::console::ConnectionPhase::Failed?"31":phase==pqvpn::console::ConnectionPhase::Disconnected?"90":"33";
    row("\033[1;36mPQVPN\033[0m  Privacy console");
    row("\033["+color+"m"+std::string(pqvpn::console::phase_label(phase))+"\033[0m");
    if(size.rows<12){row("Resize terminal for details");row("[d] connect  [x] stop  [q] quit");std::cout<<"\033[J"<<std::flush;return;}
    rule();
    row("CONFIG  "+pqvpn::console::terminal_safe(path));
    row("MODE    "+std::string(relay_only?"Relay / exit only - local traffic unchanged":"Tunnel - readiness required before Protected"));
    row("LISTEN  "+config.network.bind_address+":"+std::to_string(config.network.port));
    if(!compact){row("NODE    "+pqvpn::console::terminal_safe(executable));row("PLATFORM "+std::string(os_name())+" / "+tunnel_name());row("POLICY  "+std::string(config.security.strict_sig_verify?"Strict hybrid authentication":"Relaxed verification")+" / "+(config.security.tofu?"TOFU":"Pinned peers"));row("TRANSPORT "+std::string(config.external_transport?config.external_transport->engine:"Native UDP")+" / "+pqvpn::transport::to_string(config.adaptive_transport.mode));row("INNER   "+std::string(pqvpn::console::inner_tunnel_label(config.inner_tunnel)));}
    if(!notice.empty())row("\033[33m"+pqvpn::console::terminal_safe(notice)+"\033[0m");
    rule();
    const int available=std::max(0,size.rows-emitted-3);
    const auto lines=node.tail(static_cast<std::size_t>(available));
    for(const auto& line:lines)row(line);
    for(int i=static_cast<int>(lines.size());i<available;++i)row("");
    rule();row("[v] verify  [d] connect  [x] disconnect  [m] mode  [c] clear  [q] quit");
    std::cout<<"\033[J";
    std::cout << std::flush;
}

bool parse(int argc, char** argv, Options& options) {
    options.node = default_node(argv[0]);
    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        if(arg=="--no-tunnel")options.no_tunnel=true;
        else if(arg=="--no-inner-tunnel")options.inner_tunnel.disable=true;
        else if((arg=="--inner-tunnel-backend"||arg=="--inner-tunnel-config")&&index+1<argc){if(!pqvpn::console::parse_inner_tunnel_argument(arg,argv[++index],options.inner_tunnel))return false;}
        else if (arg == "--smoke-test") options.smoke_test = true;
        else if ((arg == "--config" || arg == "-c") && index + 1 < argc) options.config = argv[++index];
        else if (arg == "--node" && index + 1 < argc) options.node = argv[++index];
        else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: pqvpn_tui [--config PATH] [--node PATH] [--no-tunnel] [--inner-tunnel-backend wireguard|openvpn] [--inner-tunnel-config PATH] [--no-inner-tunnel] [--smoke-test]\n";
            options.help=true;return true;
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << '\n';
            return false;
        }
    }
    if(options.config.empty())options.config=pqvpn::console::default_profile(std::filesystem::path(options.node).parent_path()).generic_string();
    return !options.node.empty() && !options.config.empty() &&
           !(options.inner_tunnel.disable&&(options.inner_tunnel.backend||options.inner_tunnel.config_path));
}

std::optional<pqvpn::config::Config> load_runtime_config(const Options& options,
                                                         std::string& error) {
    auto loaded=pqvpn::config::load_config(options.config);
    if(!loaded){error="configuration is invalid";return std::nullopt;}
    if(const auto override_error=pqvpn::console::apply_inner_tunnel_override(*loaded,options.inner_tunnel)){
        error=*override_error;return std::nullopt;
    }
    if(options.no_tunnel&&loaded->inner_tunnel.enabled){error="inner tunnel requires PQVPN tunnel mode";return std::nullopt;}
    return loaded;
}

} // namespace

int main(int argc, char** argv) {
#if defined(_WIN32)
    configure_utf8_console();
#else
    setvbuf(stdout, nullptr, _IONBF, 0);
#endif
    Options options;
    if (!parse(argc, argv, options)) return argc > 1 ? 2 : 0;
    if(options.help)return 0;
    std::string config_error;
    auto loaded = load_runtime_config(options,config_error);
    if (!loaded) {
        std::cerr << "Cannot load a valid configuration: " << options.config << " (" << config_error << ")\n";
        return 1;
    }
    if (options.smoke_test) {
        std::cout << "PQVPN TUI ready on " << os_name() << " using " << tunnel_name() << '\n';
        return 0;
    }

#ifdef _WIN32
    if(!enable_vt()){
        std::cerr<<"This console does not support Windows virtual-terminal rendering. Start PQVPN Terminal Console in Windows Terminal or use the Privacy Console.\n";
        return 1;
    }
    DWORD console_mode=0;
    if(!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),&console_mode)){std::cerr<<"Interactive terminal required; use --smoke-test for automation\n";return 1;}
#else
    if(!isatty(STDIN_FILENO)||!isatty(STDOUT_FILENO)){std::cerr<<"Interactive terminal required; use --smoke-test for automation\n";return 1;}
#endif
    NodeProcess node;
    std::cout<<"\033[?1049h";
    hide_cursor();
    set_raw(true);

    const auto cleanup = [&]() {
        set_raw(false);
        show_cursor();
        std::cout << "\033[?1049l" << std::flush;
    };

    std::string notice;
    if(!options.no_tunnel)notice=tunnel_blocker();
    bool quit = false;
    while (!quit) {
        const ScreenSize size = current_size();
        render(size, *loaded, options.config, options.node, node, notice, options.no_tunnel);

        // Small pause so the terminal can breathe and keys register.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(140);
        while (std::chrono::steady_clock::now() < deadline) {
            const int key = poll_key();
            if (key >= 0) {
                const char c = static_cast<char>(key);
                if (c == 'q' || c == 'Q' || c == 3) { quit = true; break; }
                else if (c == 'c' || c == 'C') { node.clear_log(); notice.clear(); }
                else if(c=='m'||c=='M'){if(node.running())notice="Disconnect before changing mode";else if(!options.no_tunnel&&loaded->inner_tunnel.enabled)notice="Inner VPN requires tunnel mode; restart with --no-inner-tunnel to use relay mode";else{options.no_tunnel=!options.no_tunnel;if(options.no_tunnel)notice="Relay mode selected";else{notice=tunnel_blocker();if(notice.empty())notice="Tunnel mode selected";}}}
                else if(c=='v'||c=='V'||c=='r'||c=='R'){if(node.running())notice="Disconnect before changing configuration";else{std::string error;auto checked=load_runtime_config(options,error);if(checked){loaded=std::move(checked);notice=options.no_tunnel?"Configuration verified; relay mode will not protect local traffic":tunnel_blocker();if(notice.empty())notice="Configuration and tunnel readiness verified; connect when ready";}else notice="Invalid configuration: "+error;}}
                else if (c == 'd' || c == 'D') {
                    if (node.running() && !node.finished()) {
                        notice = "node already running";
                    } else {
                        if(!options.no_tunnel){notice=tunnel_blocker();if(!notice.empty())continue;}
                        std::string error;auto checked=load_runtime_config(options,error);
                        if(!checked){notice="Configuration changed or is invalid: "+error;continue;}
                        loaded=std::move(checked);
                        std::vector<std::string> arguments{"--config",options.config};if(options.no_tunnel)arguments.push_back("--no-tunnel");if(options.inner_tunnel.disable)arguments.push_back("--no-inner-tunnel");if(options.inner_tunnel.backend){arguments.push_back("--inner-tunnel-backend");arguments.push_back(*options.inner_tunnel.backend);}if(options.inner_tunnel.config_path){arguments.push_back("--inner-tunnel-config");arguments.push_back(*options.inner_tunnel.config_path);}
                        if (node.start(options.node,arguments)) {
                            notice = "node starting...";
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
