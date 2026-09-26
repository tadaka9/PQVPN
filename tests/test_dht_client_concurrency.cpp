#include <catch2/catch_test_macros.hpp>
#include "src/modules/dht_module.hpp"
#include <asio.hpp>
#include <asio/io_context.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <chrono>
#include <thread>
#include <vector>
#include <memory>

using namespace pqvpn::dht;

namespace {
// Named coroutine function (not a capturing lambda temporary): GCC 15 on
// aarch64 miscompiles coroutine lambdas passed by value through
// asio::co_spawn — the actor reads its captures from the original closure
// object after it has died. See test_peer_liveness.cpp for details.
asio::awaitable<void> drive_dht(DHTClient& c) {
    co_await c.start();
    try {
        co_await c.set("pqvpn/test", "value");
        SUCCEED("Allowed prefix set succeeded");
    } catch (const std::exception& e) {
        FAIL(std::string("Allowed prefix set failed: ") + e.what());
    }
    try {
        co_await c.set("other/test", "sometext");
        FAIL("Disallowed prefix set should have thrown");
    } catch (const std::runtime_error& e) {
        CHECK(std::string(e.what()).find("not allowed") != std::string::npos);
    }
    co_await c.stop();
}
} // namespace

TEST_CASE("DHTClient.__init__ parity: semaphore and config", "[dht][parity]") {
    DHTClient::Config config;
    config.bootstrap = {"127.0.0.1:8468", "192.168.1.1:8468"};
    config.bind = "127.0.0.1";
    config.port = 9999;
    config.strict = true;
    config.max_concurrent_sets = 2;
    config.allowed_prefixes = {"pqvpn/"};

    DHTClient client(std::move(config));

    SECTION("allowed_prefixes enforcement") {
        asio::io_context ctx;

        // 'client' outlives ctx.run(), so the reference parameters of
        // drive_dht stay valid for the whole coroutine.
        asio::co_spawn(ctx, drive_dht(client), asio::detached);

        ctx.run();
    }
}
