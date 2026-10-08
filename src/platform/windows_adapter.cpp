#include "windows_adapter.hpp"

#ifdef _WIN32

namespace pqvpn::platform {

std::unique_ptr<Adapter> make_adapter(std::string_view device_hint) {
    const bool is_device_path = device_hint.size() >= 4 && device_hint.substr(0, 4) == "\\\\.";
    return std::make_unique<WindowsOwnTunnel>(is_device_path ? std::string(device_hint) : std::string{});
}

} // namespace pqvpn::platform

#endif
