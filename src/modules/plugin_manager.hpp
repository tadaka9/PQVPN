#ifndef PQVPN_PLUGIN_MANAGER_HPP
#define PQVPN_PLUGIN_MANAGER_HPP

#include <string>
#include <vector>
#include <memory>
#include <expected>
#include <set>
#include <map>
#include <filesystem>
#include <nlohmann/json.hpp>
#include "logging_module.hpp"
#include <asio.hpp>
#include <functional>

namespace pqvpn {

class PluginManager {
public:
    struct Config {
        std::filesystem::path dir;
        std::set<std::string> enabled;
    };

    // Define a simple interface for plugins that can be teardown.
    class IPlugin {
    public:
        virtual ~IPlugin() = default;
        virtual asio::awaitable<void> teardown(std::shared_ptr<void> node) = 0;
        virtual std::string name() const = 0;
    };

    explicit PluginManager(std::shared_ptr<void> node, const nlohmann::json& config = nlohmann::json::object())
        : node_(node), config_(config)
    {
        if (config_.contains("dir") && config_["dir"].is_string()) {
            dir_ = std::filesystem::path(config_["dir"].get<std::string>());
        } else {
            dir_ = std::filesystem::current_path() / "plugins";
        }

        if (config_.contains("enabled") && config_["enabled"].is_array()) {
            for (const auto& item : config_.items()) { // wait, .items() is for objects. For array use loop
            }
            // Correct way to iterate json array:
            if (config_["enabled"].is_array()) {
                for (const auto& item : config_["enabled"]) {
                    if (item.is_string()) {
                        enabled_.insert(item.get<std::string>());
                    }
                }
            }
        }
    }

    asio::awaitable<bool> call_hook_async(const std::string& hook_name) {
        logging::Logger::info("Plugin hook '{}' called", hook_name);
        for (auto const& [name, plugin] : plugins_) {
            try {
                if (hooks_.contains(name) && hooks_[name].contains(hook_name)) {
                    bool res = co_await hooks_[name][hook_name]();
                    if (res) {
                        co_return true;
                    }
                }
            } catch (const std::exception& e) {
                logging::Logger::info("Plugin {}.{} raised: {}", name, hook_name, e.what());
            } catch (...) {
                logging::Logger::info("Plugin {}.{} raised unknown exception", name, hook_name);
            }
        }
        co_return false;
    }

    void register_hook(const std::string& plugin_name, const std::string& hook_name, std::function<asio::awaitable<bool>()> handler) {
        hooks_[plugin_name][hook_name] = handler;
    }

    void load_plugins() {
        logging::Logger::info("Loading plugins from: {}", dir_.string());
    }

    asio::awaitable<void> unload_plugins() {
        logging::Logger::info("Unloading plugins...");
        for (auto it = plugins_.begin(); it != plugins_.end(); ) {
            try {
                auto plugin = it->second;
                logging::Logger::debug("Calling teardown for plugin: {}", plugin->name());
                co_await plugin->teardown(node_);
                it = plugins_.erase(it);
            } catch (const std::exception& e) {
                logging::Logger::error("Plugin teardown raised: {}", e.what());
                ++it;
            }
        }
        logging::Logger::info("Plugins unloaded.");
        co_return;
    }

    void add_test_plugin(const std::string& name, std::shared_ptr<IPlugin> plugin) {
        plugins_[name] = plugin;
    }

private:
    std::shared_ptr<void> node_;
    nlohmann::json config_;
    std::filesystem::path dir_;
    std::set<std::string> enabled_;
    std::map<std::string, std::shared_ptr<IPlugin>> plugins_;
    std::map<std::string, std::map<std::string, std::function<asio::awaitable<bool>()>>> hooks_;
};

} // namespace pqvpn

#endif // PQVPN_PLUGIN_MANAGER_HPP
