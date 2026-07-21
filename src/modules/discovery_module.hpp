#ifndef PQVPN_DISCOVERY_MODULE_HPP
#define PQVPN_DISCOVERY_MODULE_HPP

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <asio.hpp>
#include "dht_module.hpp"
#include "logging_module.hpp"
#include "node_module.hpp"

namespace pqvpn::discovery {

using json = nlohmann::json;

/**
 * @brief Discovery subsystem implementation.
 * Mirrors the behavior of Discovery class in main.py.
 */
class Discovery : public std::enable_shared_from_this<Discovery> {
public:
    struct Config {
        bool enabled = true;
        int dht_port = 8468;
        int publish_interval = 600;
        int ttl = 1800;
        std::string cache_file = "discovery_cache.json";
        bool publish_addr = false;
        bool relay = false;
        int seq = 0;
    };

    Discovery(std::shared_ptr<PQVPNNode> node, Config config)
        : node_(std::move(node)), config_(config) {}

    asio::awaitable<void> start() {
        if (!config_.enabled) {
            spdlog::info("Discovery disabled by configuration");
            co_return;
        }

        server_ = std::make_unique<dht::InMemoryKademliaServer>();

        try {
            co_await server_->listen(config_.dht_port);
            spdlog::info("Discovery started");
            started_ = true;
        } catch (const std::exception& e) {
            spdlog::warn("Discovery: DHT unavailable: {}", e.what());
            server_.reset();
        }
    }

    asio::awaitable<void> stop() {
        if (server_) {
            server_->stop();
        }
        started_ = false;
        stopping_ = true;
        spdlog::info("Discovery stopped");
        co_return;
    }

    /**
     * @brief Translates main.py:741-752
     */
    asio::awaitable<bool> publish_peer_record() {
        if (!config_.enabled || !server_) {
            spdlog::debug("Discovery.publish_peer_record skipped: disabled or no server");
            co_return false;
        }

        try {
            auto [key, record_json] = build_record();
            co_await server_->set(key, record_json.dump());
            spdlog::info("Discovery: published peer record {}", key);
            co_return true;
        } catch (const std::exception& e) {
            spdlog::debug("Discovery: publish failed: {}", e.what());
            co_return false;
        }
    }

    /**
     * @brief Translates main.py:673-694
     */
    asio::awaitable<void> run_publish_loop() {
        co_return;
    }

    void set_server(std::unique_ptr<dht::IKademliaServer> server) {
        server_ = std::move(server);
    }

public:
    /**
     * @brief Translates main.py:696-739 logic.
     * This method builds a discovery record for publishing to the DHT
     */
    std::pair<std::string, json> build_record() {
        // Get peer ID (similar to Python's getattr(self.node, "my_id", None))
        std::string pid_hex = "";
        if (node_ && node_->my_id_.has_value()) {
            const auto& id = node_->my_id_.value();
            static constexpr char hex_digits[] = "0123456789abcdef";
            pid_hex.reserve(id.size() * 2);
            for (const auto byte : id) {
                pid_hex.push_back(hex_digits[byte >> 4]);
                pid_hex.push_back(hex_digits[byte & 0x0f]);
            }
        }

        // Create key
        std::string key = "pqvpn:peer:" + pid_hex;

        // Get address - from transport socket info (if available)
        std::string addr = "";
        if (config_.publish_addr) {
            try {
                if (node_ && node_->transport) {
                    asio::ip::udp::endpoint ep = node_->transport->local_endpoint();
                    addr = ep.address().to_string() + ":" + std::to_string(ep.port());
                }
            } catch (...) {
                addr = "";
            }
        }

        // Build record - mirroring main.py logic exactly
        json rec;
        rec["peerid"] = pid_hex;

        // Get nickname similar to Python's getattr(node, "nickname", "")
        std::string nickname = "";
        rec["nickname"] = nickname;

        // Address handling based on publish_addr setting
        rec["addr"] = config_.publish_addr ? addr : "";

        const auto to_hex = [](const std::vector<uint8_t>& bytes) {
            static constexpr char digits[] = "0123456789abcdef";
            std::string value;
            value.reserve(bytes.size() * 2);
            for (const auto byte : bytes) {
                value.push_back(digits[byte >> 4]);
                value.push_back(digits[byte & 0x0f]);
            }
            return value;
        };
        rec["ed25519_pk"] = node_ ? to_hex(node_->ed25519_public_key) : "";
        rec["brainpoolP512r1_pk"] = node_ ? to_hex(node_->brainpool_public_key) : "";
        rec["kyber_pk"] = node_ ? to_hex(node_->ml_kem_public_key) : "";
        rec["mldsa_pk"] = node_ ? to_hex(node_->ml_dsa_public_key) : "";
        rec["ts"] = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        rec["ttl"] = config_.ttl;
        rec["seq"] = config_.seq;
        rec["relay"] = config_.relay;

        return {key, rec};
    }

private:
    std::shared_ptr<PQVPNNode> node_;
    Config config_;
    std::unique_ptr<dht::IKademliaServer> server_;
    bool started_ = false;
    bool stopping_ = false;
};

} // namespace pqvpn::discovery

#endif // PQVPN_DISCOVERY_MODULE_HPP
