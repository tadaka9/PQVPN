#include "udp_protocol.hpp"
#include "node_module.hpp"

namespace pqvpn {

UDPProtocol::UDPProtocol(std::shared_ptr<PQVPNNode> node_ref) : node_(node_ref) {}

void UDPProtocol::connection_made(asio::ip::udp::socket& socket) {
    auto node_ptr = node_.lock();
    if (!node_ptr) return;
    node_ptr->transport = &socket;
}

void UDPProtocol::error_received(const asio::error_code& error) {
    (void)error;
}

void UDPProtocol::connection_lost(const asio::error_code& error) {
    (void)error;
    if (auto node_ptr = node_.lock()) {
        node_ptr->transport = nullptr;
    }
}

namespace {
asio::awaitable<void> dispatch_datagram(std::shared_ptr<PQVPNNode> node,
                                       std::vector<uint8_t> data,
                                       asio::ip::udp::endpoint endpoint) {
    co_await node->datagram_received(std::move(data), endpoint);
}
} // namespace

void UDPProtocol::datagram_received(const asio::error_code& error,
                                    const std::vector<uint8_t>& data,
                                    const asio::ip::udp::endpoint& endpoint) {
    if (error) return;
    auto node = node_.lock();
    if (!node) return;

    // The node owns outer-frame validation and authenticated dispatch. Keep
    // the complete frame, matching main.py's _UDPProtocol receive path.
    auto executor = node->get_io_context().get_executor();
    asio::co_spawn(executor, dispatch_datagram(std::move(node), data, endpoint),
                   asio::detached);
}

} // namespace pqvpn
