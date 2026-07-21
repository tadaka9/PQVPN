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

void UDPProtocol::datagram_received(const asio::error_code& error, const std::vector<uint8_t>& data,
                                    const asio::ip::udp::endpoint& endpoint) {
    if (error || data.size() < 2) return;

    auto node_ptr = node_.lock();
    if (!node_ptr) return;

    if (data[0] != 1) return; // Version mismatch

    uint8_t type = data[1];
    std::vector<uint8_t> payload(data.begin() + 2, data.end());

    if (type == 1) { // RELAY/DATA
        asio::co_spawn(node_ptr->get_io_context(),
                       node_ptr->datagram_received(std::move(payload), endpoint),
                       asio::detached);
    } else if (type == 2) { // HELLO
        asio::co_spawn(node_ptr->get_io_context(),
                       node_ptr->handle_hello(payload, {}, {}, 0),
                       asio::detached);
    } else if (type == 3) { // GOSSIP
        asio::co_spawn(node_ptr->get_io_context(),
                       node_ptr->handle_gossip(std::move(payload), endpoint),
                       asio::detached);
    }
}

asio::awaitable<void> UDPProtocol::handle_gossip(std::vector<uint8_t> payload, asio::ip::udp::endpoint endpoint) {
    auto node_ptr = node_.lock();
    if (!node_ptr || payload.size() < 2) co_return;

    try {
        // Payload format: [Version(1)] + [EntryCount(2)] + [Entries...]
        if (payload[0] != 1) co_return; // Version check

        size_t offset = 2;
        uint16_t entry_count = (static_cast<uint16_t>(payload[offset]) << 8) | payload[offset + 1];
        offset += 2;

        for (uint16_t i = 0; i < entry_count && offset < payload.size(); ++i) {
            // Entry format: [PeerID_Len(1)] + [PeerID] + [Nickname_Len(1)] + [Nickname] + [IsRelay(1)]
            if (offset + 1 > payload.size()) break;
            uint8_t id_len = payload[offset++];

            if (offset + id_len > payload.size()) break;
            std::vector<uint8_t> peer_id(payload.begin() + offset, payload.begin() + offset + id_len);
            offset += id_len;

            if (offset + 1 > payload.size()) break;
            uint8_t name_len = payload[offset++];

            if (offset + name_len > payload.size()) break;
            std::string nickname(payload.begin() + offset, payload.begin() + offset + name_len);
            offset += name_len;

            if (offset + 1 > payload.size()) break;
            bool is_relay = (payload[offset++] != 0);

            node_ptr->handle_gossip_update(peer_id, nickname, is_relay);
        }
    } catch (...) {
        // Malformed gossip payload - drop it safely
    }
    co_return;
}

} // namespace pqvpn
