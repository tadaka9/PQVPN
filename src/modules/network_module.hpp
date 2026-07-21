#ifndef PQVPN_NETWORK_HPP
#define PQVPN_NETWORK_HPP

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <expected>
#include <array>
#include <functional>
#include <asio.hpp>
#include <spdlog/spdlog.h>
#include "config_module.hpp"
#include "dht_module.hpp"

namespace pqvpn::network {

enum class NetworkError {
    SocketCreationFailed,
    BindFailed,
    ListenFailed,
    ReceiveFailed,
    SendFailed,
    AddressInvalid,
    Unknown
};

class NetworkModule {
public:
    virtual ~NetworkModule() = default;
    virtual std::expected<void, NetworkError> start() = 0;
    virtual void stop() = 0;
};

// A UDP listener using Asio.
class UdpListener : public NetworkModule {
public:
    using ReceiveHandler = std::function<void(std::vector<uint8_t>, const asio::ip::udp::endpoint&)>;

    UdpListener(asio::io_context& io_context, uint16_t port)
        : io_context_(io_context),
          port_(port),
          socket_(io_context) {}

    UdpListener(asio::io_context& io_context, const config::NetworkConfig& config)
        : io_context_(io_context), port_(config.port),
          bind_address_(config.bind_address), socket_(io_context) {}

    explicit UdpListener(const config::NetworkConfig& config)
        : owned_io_(std::make_shared<asio::io_context>()),
          io_context_(*owned_io_), port_(config.port),
          bind_address_(config.bind_address), socket_(io_context_) {}

    std::expected<void, NetworkError> start() override {
        try {
            if (port_ == 0) return std::unexpected(NetworkError::AddressInvalid);
            std::error_code address_error;
            const auto address = asio::ip::make_address(bind_address_, address_error);
            if (address_error) return std::unexpected(NetworkError::AddressInvalid);
            asio::ip::udp::endpoint endpoint(address, port_);
            socket_.open(endpoint.protocol());
            socket_.bind(endpoint);
            receive_next();
            spdlog::info("UDP Listener started on port {}", port_);
            return {};
        } catch (const std::exception& e) {
            spdlog::error("Failed to start UDP listener: {}", e.what());
            return std::unexpected(NetworkError::BindFailed);
        }
    }

    void stop() override {
        if (socket_.is_open()) {
            std::error_code ec;
            socket_.shutdown(asio::ip::udp::socket::shutdown_both, ec);
            socket_.close(ec);
            spdlog::info("UDP Listener stopped.");
        }
    }

    bool is_running() const { return socket_.is_open(); }
    asio::ip::udp::socket& socket() { return socket_; }
    const asio::ip::udp::socket& socket() const { return socket_; }
    void set_receive_handler(ReceiveHandler handler) { receive_handler_ = std::move(handler); }

private:
    void receive_next() {
        socket_.async_receive_from(asio::buffer(receive_buffer_), remote_endpoint_,
            [this](const asio::error_code& error, const std::size_t bytes_received) {
                if (!error) {
                    if (receive_handler_) {
                        receive_handler_(
                            std::vector<uint8_t>(receive_buffer_.begin(), receive_buffer_.begin() + bytes_received),
                            remote_endpoint_);
                    }
                    receive_next();
                } else if (error != asio::error::operation_aborted) {
                    spdlog::error("UDP receive failed: {}", error.message());
                    receive_next();
                }
            });
    }

    std::shared_ptr<asio::io_context> owned_io_;
    asio::io_context& io_context_;
    uint16_t port_;
    std::string bind_address_ = "0.0.0.0";
    asio::ip::udp::socket socket_;
    std::array<uint8_t, 65536> receive_buffer_{};
    asio::ip::udp::endpoint remote_endpoint_;
    ReceiveHandler receive_handler_;
};

using UDPListener = UdpListener;

} // namespace pqvpn::network

#endif // PQVPN_NETWORK_HPP
