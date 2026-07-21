#ifndef PQVPN_DHT_MODULE_CPP
#define PQVPN_DHT_MODULE_CPP

#include "src/modules/dht_module.hpp"
#include <asio.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <iostream>

namespace pqvpn::dht {

asio::awaitable<void> DHTClient::start() {
    if (started_) co_return;

    try {
        // For this port, we default to InMemory if no server is provided.
        server_ = std::make_unique<InMemoryKademliaServer>();

        co_await server_->listen(config_.port);

        if (!config_.bootstrap.empty()) {
            try {
                std::vector<std::pair<std::string, uint16_t>> bootstrap_nodes;
                for (const auto& b : config_.bootstrap) {
                    size_t pos = b.find(':');
                    if (pos != std::string::npos) {
                        bootstrap_nodes.emplace_back(b.substr(0, pos), static_cast<uint16_t>(std::stoi(b.substr(pos + 1))));
                    } else {
                        // Fallback for simple host-only bootstrap entries if needed
                        bootstrap_nodes.emplace_back(b, 8468);
                    }
                }
                co_await server_->bootstrap(bootstrap_nodes);
                spdlog::info("DHT bootstrapped to {} nodes", bootstrap_nodes.size());
            } catch (const std::exception& e) {
                spdlog::debug("DHT bootstrap failure: {}", e.what());
            }
        }

        started_ = true;
        spdlog::info("DHT client started on port {}", config_.port);
    } catch (const std::exception& e) {
        spdlog::error("DHT start failed: {}", e.what());
        server_ = nullptr;
        if (config_.strict) {
            throw;
        }
    }
    co_return;
}

asio::awaitable<void> DHTClient::stop() {
    if (!started_) co_return;

    try {
        if (server_) {
            server_->stop();
        }
    } catch (...) {
        // swallow as Python does
    }

    server_ = nullptr;
    started_ = false;
    spdlog::info("DHT client stopped");
    co_return;
}

asio::awaitable<void> DHTClient::set(const std::string& key, const std::string& value) {
    if (config_.strict && !config_.allowed_prefixes.empty()) {
        bool allowed = false;
        for (const auto& prefix : config_.allowed_prefixes) {
            if (key.find(prefix) == 0) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            throw std::runtime_error("DHTClient.set: key '" + key + "' not allowed by allowed_prefixes");
        }
    }

    if (!started_ || !server_) {
        throw std::runtime_error("DHT client not started");
    }

    while (true) {
        {
            std::lock_guard<std::mutex> lock(set_mutex_);
            if (active_sets_ < max_concurrent_sets_) {
                active_sets_++;
                break;
            }
        }
        const auto executor = co_await asio::this_coro::executor;
        co_await asio::post(executor, asio::use_awaitable);
    }

    try {
        co_await server_->set(key, value);
    } catch (const std::exception& e) {
        spdlog::debug("DHT set failed for key={}: {}", key, e.what());
        {
            std::lock_guard<std::mutex> lock(set_mutex_);
            active_sets_--;
        }
        throw;
    }

    {
        std::lock_guard<std::mutex> lock(set_mutex_);
        active_sets_--;
    }
    co_return;
}

asio::awaitable<std::string> DHTClient::get(const std::string& key) {
    if (!started_ || !server_) {
        throw std::runtime_error("DHT client not started");
    }

    try {
        std::string val = co_await server_->get(key);
        co_return val;
    } catch (const std::exception& e) {
        spdlog::debug("DHT get failed for key={}: {}", key, e.what());
        co_return "";
    }
}

} // namespace pqvpn::dht

#endif // PQVPN_DHT_MODULE_CPP
