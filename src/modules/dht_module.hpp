#ifndef PQVPN_DHT_MODULE_HPP
#define PQVPN_DHT_MODULE_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <expected>
#include <system_error>
#include <functional>
#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/channel.hpp>
#include <spdlog/spdlog.h>

namespace pqvpn::dht {

/**
 * @brief Interface for a Kademlia-like Server.
 * Mirrors the behavior required by DHTClient in main.py.
 */
class IKademliaServer {
public:
    virtual ~IKademliaServer() = default;
    virtual asio::awaitable<void> listen(uint16_t port) = 0;
    virtual asio::awaitable<void> bootstrap(const std::vector<std::pair<std::string, uint16_t>>& bootstrap_nodes) = 0;
    virtual asio::awaitable<void> set(const std::string& key, const std::string& value) = 0;
    virtual asio::awaitable<std::string> get(const std::string& key) = 0;
    virtual void stop() = 0;
};

/**
 * @brief An in-memory implementation of KademliaServer.
 * Used for fallback/testing when a real network DHT is unavailable.
 */
class InMemoryKademliaServer : public IKademliaServer {
public:
    InMemoryKademliaServer() = default;

    asio::awaitable<void> listen(uint16_t port) override {
        port_ = port;
        spdlog::info("InMemory DHT Server listening on port {}", port_);
        co_return;
    }

    asio::awaitable<void> bootstrap(const std::vector<std::pair<std::string, uint16_t>>& bootstrap_nodes) override {
        for (const auto& [host, port] : bootstrap_nodes) {
            spdlog::debug("InMemory DHT: bootstrapping to {}:{}", host, port);
        }
        co_return;
    }

    asio::awaitable<void> set(const std::string& key, const std::string& value) override {
        store_[key] = value;
        spdlog::debug("InMemory DHT: set {}={}", key, value);
        co_return;
    }

    asio::awaitable<std::string> get(const std::string& key) override {
        auto it = store_.find(key);
        if (it != store_.end()) {
            co_return it->second;
        }
        co_return "";
    }

    void stop() override {
        spdlog::info("InMemory DHT Server stopped.");
    }

private:
    uint16_t port_{0};
    std::map<std::string, std::string> store_;
};

/**
 * @brief Small hardened DHT client used by Discovery (in-file copy).
 */
class DHTClient : public std::enable_shared_from_this<DHTClient> {
public:
    struct Config {
        std::vector<std::string> bootstrap;
        std::string bind = "0.0.0.0";
        uint16_t port = 8468;
        bool strict = true;
        int max_concurrent_sets = 4;
        std::vector<std::string> allowed_prefixes;
    };

    DHTClient(Config config)
        : config_(std::move(config)),
          max_concurrent_sets_(config_.max_concurrent_sets),
          active_sets_(0),
          started_(false) {}

    asio::awaitable<void> start();
    asio::awaitable<void> stop();
    asio::awaitable<void> set(const std::string& key, const std::string& value);
    asio::awaitable<std::string> get(const std::string& key);

private:
    Config config_;
    std::unique_ptr<IKademliaServer> server_;
    bool started_{false};
    std::mutex set_mutex_;
    int active_sets_{0};
    int max_concurrent_sets_{0};
};

/**
 * @brief Factory function to create a Kademlia server.
 */
using KademliaServerFactory = std::function<std::unique_ptr<IKademliaServer>()>;

inline std::unique_ptr<IKademliaServer> create_kademlia_server(
    const KademliaServerFactory& configured_factory = {},
    const KademliaServerFactory& late_import_factory = {}) noexcept {
    try {
        if (configured_factory) {
            return configured_factory();
        }
        if (late_import_factory) {
            try {
                return late_import_factory();
            } catch (...) {
                return nullptr;
            }
        }
    } catch (...) {
        return nullptr;
    }
    return nullptr;
}

} // namespace pqvpn::dht

#endif // PQVPN_DHT_MODULE_HPP
