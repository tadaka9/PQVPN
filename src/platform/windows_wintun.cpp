#ifdef _WIN32

#include "windows_wintun.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace pqvpn::platform {
namespace {

using WintunAdapterHandle = void*;
using WintunSessionHandle = void*;

constexpr DWORD ring_capacity = 0x20000; // 128 KiB; valid Wintun power of two.
constexpr std::size_t maximum_packet_size = 0xffff;

std::runtime_error windows_error(const std::string_view operation, const DWORD code = GetLastError()) {
    return std::runtime_error(std::string(operation) + " failed (Windows error " +
        std::to_string(code) + ")");
}

std::wstring widen_ascii(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) throw windows_error("UTF-8 adapter-name conversion");
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), size) != size) {
        throw windows_error("UTF-8 adapter-name conversion");
    }
    return result;
}

template <typename Function>
Function load_function(HMODULE module, const char* name) {
    const auto address = GetProcAddress(module, name);
    if (!address) throw windows_error(std::string("loading Wintun export ") + name);
    static_assert(sizeof(Function) == sizeof(address));
    Function function{};
    std::memcpy(&function, &address, sizeof(function));
    return function;
}

} // namespace

struct WindowsWintun::Api {
    using OpenAdapter = WintunAdapterHandle(WINAPI*)(const wchar_t*);
    using CreateAdapter = WintunAdapterHandle(WINAPI*)(const wchar_t*, const wchar_t*, const GUID*);
    using CloseAdapter = void(WINAPI*)(WintunAdapterHandle);
    using StartSession = WintunSessionHandle(WINAPI*)(WintunAdapterHandle, DWORD);
    using EndSession = void(WINAPI*)(WintunSessionHandle);
    using GetReadWaitEvent = HANDLE(WINAPI*)(WintunSessionHandle);
    using ReceivePacket = BYTE*(WINAPI*)(WintunSessionHandle, DWORD*);
    using ReleaseReceivePacket = void(WINAPI*)(WintunSessionHandle, const BYTE*);
    using AllocateSendPacket = BYTE*(WINAPI*)(WintunSessionHandle, DWORD);
    using SendPacket = void(WINAPI*)(WintunSessionHandle, const BYTE*);

    explicit Api(HMODULE module)
        : open_adapter(load_function<OpenAdapter>(module, "WintunOpenAdapter")),
          create_adapter(load_function<CreateAdapter>(module, "WintunCreateAdapter")),
          close_adapter(load_function<CloseAdapter>(module, "WintunCloseAdapter")),
          start_session(load_function<StartSession>(module, "WintunStartSession")),
          end_session(load_function<EndSession>(module, "WintunEndSession")),
          get_read_wait_event(load_function<GetReadWaitEvent>(module, "WintunGetReadWaitEvent")),
          receive_packet(load_function<ReceivePacket>(module, "WintunReceivePacket")),
          release_receive_packet(load_function<ReleaseReceivePacket>(module, "WintunReleaseReceivePacket")),
          allocate_send_packet(load_function<AllocateSendPacket>(module, "WintunAllocateSendPacket")),
          send_packet(load_function<SendPacket>(module, "WintunSendPacket")) {}

    OpenAdapter open_adapter;
    CreateAdapter create_adapter;
    CloseAdapter close_adapter;
    StartSession start_session;
    EndSession end_session;
    GetReadWaitEvent get_read_wait_event;
    ReceivePacket receive_packet;
    ReleaseReceivePacket release_receive_packet;
    AllocateSendPacket allocate_send_packet;
    SendPacket send_packet;
};

WindowsWintun::~WindowsWintun() { close(); }

bool WindowsWintun::is_open() const noexcept {
    std::scoped_lock lock(mutex_);
    return session_ != nullptr;
}

std::string WindowsWintun::name() const {
    std::scoped_lock lock(mutex_);
    return name_.empty() ? configured_name_ : name_;
}

void WindowsWintun::start(PacketHandler packet_handler, ErrorHandler error_handler) {
    error_handler_ = std::move(error_handler);
    open(configured_name_, std::move(packet_handler));
}

void WindowsWintun::open(const std::string& adapter_name, PacketHandler handler) {
    if (!handler) throw std::invalid_argument("Wintun packet handler is required");
    std::scoped_lock lock(mutex_);
    if (session_) throw std::logic_error("Wintun adapter is already open");

    name_ = adapter_name.empty() ? "PQVPN" : adapter_name;
    try {
        module_ = LoadLibraryExW(L"wintun.dll", nullptr,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module_) throw windows_error("loading wintun.dll");
        api_ = new Api(module_);

        const auto wide_name = widen_ascii(name_);
        adapter_ = api_->open_adapter(wide_name.c_str());
        if (!adapter_ && GetLastError() == ERROR_FILE_NOT_FOUND) {
            adapter_ = api_->create_adapter(wide_name.c_str(), L"PQVPN", nullptr);
        }
        if (!adapter_) throw windows_error("opening or creating Wintun adapter");

        session_ = api_->start_session(adapter_, ring_capacity);
        if (!session_) throw windows_error("starting Wintun session");
        stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event_) throw windows_error("creating Wintun stop event");
        handler_ = std::move(handler);
        receiver_ = std::jthread([this](const std::stop_token token) { receive_loop(token); });
    } catch (...) {
        if (stop_event_) CloseHandle(stop_event_);
        stop_event_ = nullptr;
        if (session_ && api_) api_->end_session(session_);
        session_ = nullptr;
        if (adapter_ && api_) api_->close_adapter(adapter_);
        adapter_ = nullptr;
        delete api_;
        api_ = nullptr;
        if (module_) FreeLibrary(module_);
        module_ = nullptr;
        handler_ = {};
        name_.clear();
        throw;
    }
}

void WindowsWintun::receive_loop(const std::stop_token stop_token) noexcept {
    const auto report_error = [this](std::string message) noexcept {
        try {
            if (error_handler_) error_handler_(std::move(message));
        } catch (...) {
        }
    };
    for (;;) {
        if (stop_token.stop_requested()) return;
        DWORD size = 0;
        BYTE* packet = api_->receive_packet(session_, &size);
        if (packet) {
            try {
                if (size > 0 && size <= maximum_packet_size && handler_) {
                    handler_(std::vector<uint8_t>(packet, packet + size));
                }
            } catch (const std::exception& error) {
                report_error(std::string("Wintun packet callback failed: ") + error.what());
            } catch (...) {
                report_error("Wintun packet callback failed with an unknown exception");
            }
            api_->release_receive_packet(session_, packet);
            continue;
        }

        const DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_ITEMS) {
            report_error("receiving Wintun packet failed (Windows error " + std::to_string(error) + ")");
            return;
        }
        HANDLE events[] = {api_->get_read_wait_event(session_), stop_event_};
        if (!events[0]) {
            report_error("getting Wintun read event failed (Windows error " +
                std::to_string(GetLastError()) + ")");
            return;
        }
        const DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0 + 1 || stop_token.stop_requested()) return;
        if (wait != WAIT_OBJECT_0) {
            report_error("waiting for Wintun packet failed (Windows error " +
                std::to_string(GetLastError()) + ")");
            return;
        }
    }
}

void WindowsWintun::write(const std::span<const uint8_t> packet) {
    if (packet.empty() || packet.size() > maximum_packet_size ||
        packet.size() > std::numeric_limits<DWORD>::max()) {
        throw std::invalid_argument("invalid Wintun layer-3 packet size");
    }
    std::scoped_lock lock(mutex_);
    if (!session_ || !api_) throw std::logic_error("Wintun adapter is closed");
    BYTE* destination = api_->allocate_send_packet(session_, static_cast<DWORD>(packet.size()));
    if (!destination) throw windows_error("allocating Wintun send packet");
    std::copy(packet.begin(), packet.end(), destination);
    api_->send_packet(session_, destination);
}

void WindowsWintun::close() noexcept {
    {
        std::scoped_lock lock(mutex_);
        if (!module_) return;
        receiver_.request_stop();
        if (stop_event_) SetEvent(stop_event_);
    }
    if (receiver_.joinable()) receiver_.join();

    std::scoped_lock lock(mutex_);
    if (session_ && api_) api_->end_session(session_);
    session_ = nullptr;
    if (adapter_ && api_) api_->close_adapter(adapter_);
    adapter_ = nullptr;
    if (stop_event_) CloseHandle(stop_event_);
    stop_event_ = nullptr;
    handler_ = {};
    error_handler_ = {};
    delete api_;
    api_ = nullptr;
    if (module_) FreeLibrary(module_);
    module_ = nullptr;
    name_.clear();
}

} // namespace pqvpn::platform

#endif
