#pragma once
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <stdexcept>

namespace pqvpn {
// External UDP forwarders own their process, credentials and raw-socket
// privileges. PQVPN only talks to the explicitly selected loopback endpoint.
struct ExternalTransport {
    std::string engine;
    std::string host = "127.0.0.1";
    int port = 0;
    asio::ip::udp::endpoint endpoint() const {
        auto address = asio::ip::make_address(host);
        if (engine != "udp2raw" && engine != "udp-forwarder")
            throw std::invalid_argument("external transport requires a UDP forwarder; SOCKS engines need a TCP relay");
        if (!address.is_loopback() || port < 1 || port > 65535)
            throw std::invalid_argument("external transport must use a valid loopback endpoint");
        return {address, static_cast<unsigned short>(port)};
    }
    friend void from_json(const nlohmann::json& j, ExternalTransport& value) {
        if (j.at("version").get<int>() != 1 || j.at("mode").get<std::string>() != "attach")
            throw std::invalid_argument("external transport requires version 1 and attach mode");
        value.engine = j.at("engine").get<std::string>();
        value.host = j.at("host").get<std::string>();
        value.port = j.at("port").get<int>();
        (void)value.endpoint();
    }
    friend void to_json(nlohmann::json& j, const ExternalTransport& value) {
        j = {{"version", 1}, {"mode", "attach"}, {"engine", value.engine},
             {"host", value.host}, {"port", value.port}};
    }
};

inline bool transport_allows(asio::ip::udp::socket* socket, const asio::ip::udp::endpoint& destination) {
    if (!socket) return false;
    asio::error_code error;
    const auto attached = socket->remote_endpoint(error);
    // An unconnected socket is the ordinary mesh transport. A connected
    // socket is pinned to its external engine: reject every alternate route.
    return error == asio::error::not_connected || (!error && attached == destination);
}
}
