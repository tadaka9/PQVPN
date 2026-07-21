#ifdef _WIN32

#include "windows_tap.hpp"

#include <array>
#include <cwctype>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include <iphlpapi.h>

namespace pqvpn::platform {
namespace {

constexpr std::string_view adapter_class =
    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
constexpr ULONG tap_control_code(const ULONG request) {
    return CTL_CODE(FILE_DEVICE_UNKNOWN, request, METHOD_BUFFERED, FILE_ANY_ACCESS);
}
constexpr ULONG tap_set_media_status = tap_control_code(6);

std::string registry_string(HKEY key, const char* name) {
    std::array<char, 512> value{};
    DWORD type = 0;
    DWORD size = static_cast<DWORD>(value.size());
    if (RegQueryValueExA(key, name, nullptr, &type,
            reinterpret_cast<BYTE*>(value.data()), &size) != ERROR_SUCCESS || type != REG_SZ) {
        return {};
    }
    return std::string(value.data());
}

} // namespace

WindowsTap::~WindowsTap() { close(); }

std::string WindowsTap::find_adapter_guid() {
    ULONG size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr, nullptr, &size)
            == ERROR_BUFFER_OVERFLOW) {
        std::vector<uint8_t> storage(size);
        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr,
                adapters, &size) == NO_ERROR) {
            for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
                std::wstring description = adapter->Description ? adapter->Description : L"";
                for (auto& character : description) character = std::towlower(character);
                if ((description.find(L"tap-windows") != std::wstring::npos ||
                     description.find(L"tap adapter") != std::wstring::npos) &&
                    adapter->AdapterName && *adapter->AdapterName) {
                    return adapter->AdapterName;
                }
            }
        }
    }

    // Compatibility fallback for older TAP-Windows installers.
    HKEY class_key = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, adapter_class.data(), 0, KEY_READ, &class_key) != ERROR_SUCCESS) {
        throw std::runtime_error("cannot inspect TAP-Windows adapters in the registry");
    }
    std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> guard(class_key, RegCloseKey);

    for (DWORD index = 0;; ++index) {
        std::array<char, 256> subkey_name{};
        DWORD name_size = static_cast<DWORD>(subkey_name.size());
        const auto enumerated = RegEnumKeyExA(class_key, index, subkey_name.data(), &name_size,
            nullptr, nullptr, nullptr, nullptr);
        if (enumerated == ERROR_NO_MORE_ITEMS) break;
        if (enumerated != ERROR_SUCCESS) continue;
        HKEY adapter_key = nullptr;
        if (RegOpenKeyExA(class_key, subkey_name.data(), 0, KEY_READ, &adapter_key) != ERROR_SUCCESS) continue;
        std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> adapter_guard(adapter_key, RegCloseKey);
        const auto component = registry_string(adapter_key, "ComponentId");
        if (component.rfind("tap", 0) == 0) {
            const auto guid = registry_string(adapter_key, "NetCfgInstanceId");
            if (!guid.empty()) return guid;
        }
    }
    throw std::runtime_error("no TAP-Windows adapter found; install TAP-Windows and create an adapter first");
}

void WindowsTap::open(const std::string& requested_guid, PacketHandler handler) {
    if (is_open()) throw std::logic_error("TAP adapter is already open");
    guid_ = requested_guid.empty() ? find_adapter_guid() : requested_guid;
    const auto path = "\\\\.\\Global\\" + guid_ + ".tap";
    device_ = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, nullptr);
    if (device_ == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot open TAP-Windows adapter " + guid_ +
            "; run as Administrator and verify the adapter GUID");
    }
    ULONG connected = 1;
    DWORD returned = 0;
    if (!DeviceIoControl(device_, tap_set_media_status, &connected, sizeof(connected),
            &connected, sizeof(connected), &returned, nullptr)) {
        close();
        throw std::runtime_error("cannot enable TAP-Windows media status");
    }
    handler_ = std::move(handler);
    reader_ = std::jthread([this](const std::stop_token token) { read_loop(token); });
}

void WindowsTap::read_loop(const std::stop_token stop_token) {
    std::array<uint8_t, 65536> buffer{};
    while (!stop_token.stop_requested() && is_open()) {
        DWORD received = 0;
        if (!ReadFile(device_, buffer.data(), static_cast<DWORD>(buffer.size()), &received, nullptr)) {
            if (GetLastError() == ERROR_OPERATION_ABORTED || stop_token.stop_requested()) return;
            return;
        }
        if (received && handler_) handler_(std::vector<uint8_t>(buffer.begin(), buffer.begin() + received));
    }
}

void WindowsTap::write(const std::vector<uint8_t>& ethernet_frame) {
    if (!is_open()) throw std::logic_error("TAP adapter is closed");
    if (ethernet_frame.empty() || ethernet_frame.size() > 65536) {
        throw std::invalid_argument("invalid TAP Ethernet frame size");
    }
    DWORD written = 0;
    if (!WriteFile(device_, ethernet_frame.data(), static_cast<DWORD>(ethernet_frame.size()), &written, nullptr) ||
        static_cast<size_t>(written) != ethernet_frame.size()) {
        throw std::runtime_error("TAP-Windows write failed");
    }
}

void WindowsTap::close() noexcept {
    if (device_ == INVALID_HANDLE_VALUE) return;
    reader_.request_stop();
    CancelIoEx(device_, nullptr);
    CloseHandle(device_);
    device_ = INVALID_HANDLE_VALUE;
    if (reader_.joinable()) reader_.join();
    handler_ = {};
}

} // namespace pqvpn::platform

#endif
