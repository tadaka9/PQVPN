#include <catch2/catch_test_macros.hpp>
#include "plugin_manager.hpp"
#include <asio.hpp>
#include <memory>

class MockPlugin : public pqvpn::PluginManager::IPlugin {
public:
    MockPlugin(std::string name) : name_(name) {}
    asio::awaitable<void> teardown(std::shared_ptr<void> node) override {
        co_return;
    }
    std::string name() const override { return name_; }
private:
    std::string name_;
};

namespace {
// Named coroutine function (not a capturing lambda temporary): GCC 15 on
// aarch64 miscompiles coroutine lambdas passed by value through
// asio::co_spawn — the actor reads its captures from the original closure
// object after it has died. See test_peer_liveness.cpp for details.
asio::awaitable<void> invoke_hook(pqvpn::PluginManager& pm, const char* name, bool& out) {
    out = co_await pm.call_hook_async(name);
}
} // namespace

TEST_CASE("PluginManager call_hook_async", "[plugin_manager]") {
    auto node = std::make_shared<int>(42);
    pqvpn::PluginManager pm(node, nlohmann::json::object());

    auto p1 = std::make_shared<MockPlugin>("p1");
    auto p2 = std::make_shared<MockPlugin>("p2");
    pm.add_test_plugin("p1", p1);
    pm.add_test_plugin("p2", p2);

    // Define a hook that returns true
    pm.register_hook("p1", "on_start", []() -> asio::awaitable<bool> {
        co_return true;
    });

    // Define a hook that returns false
    pm.register_hook("p2", "on_start", []() -> asio::awaitable<bool> {
        co_return false;
    });

    asio::io_context ctx;
    bool result = false;

    asio::co_spawn(ctx, invoke_hook(pm, "on_start", result), asio::detached);

    ctx.run();

    REQUIRE(result == true);

    // Reset result for the next check
    result = false;

    // Define a hook that throws
    pm.register_hook("p1", "on_error", []() -> asio::awaitable<bool> {
        throw std::runtime_error("Boom");
    });

    // Define a second plugin that returns false so we can verify the loop continues and eventually returns false
    pm.register_hook("p2", "on_error", []() -> asio::awaitable<bool> {
        co_return false;
    });

    asio::co_spawn(ctx, invoke_hook(pm, "on_error", result), asio::detached);

    ctx.run();

    REQUIRE(result == false);
}
