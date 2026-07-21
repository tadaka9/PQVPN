#ifndef PQVPN_UDP_PROTOCOL_HPP
#define PQVPN_UDP_PROTOCOL_HPP

#include <memory>
#include <asio.hpp>
#include <vector>

namespace pqvpn {

class PQVPNNode; // Forward declaration

/**
 * @brief ASIO-based UDP protocol implementation matching the Python _UDPProtocol behavior.
 */
class UDPProtocol : public std::enable_shared_from_this<UDPProtocol> {
public:
    explicit UDPProtocol(std::shared_ptr<PQVPNNode> node_ref);

    void connection_made(asio::ip::udp::socket& socket);
    void datagram_received(const asio::error_code& error, const std::vector<uint8_t>& data,
                           const asio::ip::udp::endpoint& endpoint);
    void error_received(const asio::error_code& error);
    void connection_lost(const asio::error_code& error);

    // New gossip handler
    asio::awaitable<void> handle_gossip(std::vector<uint8_t> payload, asio::ip::udp::endpoint endpoint);

private:
    std::weak_ptr<PQVPNNode> node_;
};

} // namespace pqvpn

#endif // PQVPN_UDP_PROTOCOL_HPP
