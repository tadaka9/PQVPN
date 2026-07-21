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

        asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
            // We need to use the client. Since it's in the scope of this test case,
            // we can capture by reference. 'ctx.run()' blocks until all tasks are done.
            // The lifetime of 'client' is safe here because ctx.run() happens before it goes out of scope.

            // Use a pointer or reference to avoid moving the client itself in the lambda
            auto& c = client;

            // Start the client (this creates the InMemory server)
            co_await c.start();

            // Test allowed prefix
            try {
                co_await c.set("pqvpn/test", "value");
                SUCCEED("Allowed prefix set succeeded");
            } catch (const std::exception& e) {
                FAIL(std::string("Allowed prefix set failed: ") + e.what());
            }

            // Test disallowed prefix
            try {
                co_await c.set("other/test", "sometext");
                FAIL("Disallowed prefix set should have thrown");
            } catch (const std::runtime_error& e) {
                CHECK(std::string(e.what()).find("not allowed") != std::string::npos);
            }

            co_await c.stop();
        }, asio::detached);

        ctx.run();
    }
}
