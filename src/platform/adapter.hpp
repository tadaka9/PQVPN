#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace pqvpn::platform {

// Uniform tunnel-device boundary for the portable PQVPN core. Each supported
// OS provides one implementation through make_adapter(): a TAP-Windows device
// on Windows, a /dev/net/tun layer-3 interface on Linux, and the Network
// Extension bridge on macOS.
//
// The interface is exception-free by contract: every operation reports its
// outcome by return value so the node can degrade to UDP-only mode (or fail
// closed, per OS policy) instead of unwinding a coroutine from device code.
class Adapter {
public:
    using Packet = std::vector<std::uint8_t>;
    // Invoked on the device reader thread for every inbound IP packet.
    // Implementations must not block; forward to the io_context immediately.
    using InboundHandler = std::function<void(Packet)>;

    virtual ~Adapter() = default;

    // Open the tunnel device and start delivering inbound packets to `inbound`.
    // Returns false (never throws) when the device cannot be opened.
    [[nodiscard]] virtual bool open(InboundHandler inbound) = 0;

    // Deliver one core packet (a single IPv4/IPv6 datagram) to the device.
    // Returns false when the adapter is closed or the write fails.
    [[nodiscard]] virtual bool write(const Packet& packet) noexcept = 0;

    // Release the device and stop inbound delivery. Idempotent per OS.
    virtual void close() noexcept = 0;

    [[nodiscard]] virtual bool is_open() const noexcept = 0;

    // Human-readable identity for logs: adapter GUID, interface name, or the
    // extension boundary in use. Must not be empty.
    [[nodiscard]] virtual std::string describe() const = 0;
};

// Per-OS factory (defined by the host OS's platform sources). device_hint
// selects a specific device where the OS supports it — a TAP-Windows GUID on
// Windows, an interface name on Linux — and is ignored on macOS. Construction
// must not touch any device; only open() may do that.
std::unique_ptr<Adapter> make_adapter(std::string_view device_hint = {});

} // namespace pqvpn::platform
