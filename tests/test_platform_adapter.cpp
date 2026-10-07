#include <catch2/catch_test_macros.hpp>

#include "platform/adapter.hpp"

#include <atomic>

using pqvpn::platform::Adapter;
using Packet = Adapter::Packet;

// In-memory device standing in for a real TAP/TUN/extension boundary, so the
// portable core's adapter contract can be exercised on every OS without
// privileges. Mirrors the ScriptedRouteBackend pattern used by the routing tests.
class ScriptedAdapter : public Adapter {
public:
    bool open(InboundHandler inbound) override {
        if (open_should_fail_ || !inbound) return false;
        inbound_ = std::move(inbound);
        opened_ = true;
        return opened_;
    }

    [[nodiscard]] bool write(const Packet& packet) noexcept override {
        if (!is_open()) return false;
        outbound_.push_back(packet);
        // Delivery is only accepted when it was recorded intact.
        return outbound_.back() == packet;
    }

    void close() noexcept override {
        closed_ = true;
        inbound_ = {};
    }

    [[nodiscard]] bool is_open() const noexcept override { return opened_ && !closed_; }
    [[nodiscard]] std::string describe() const override { return "scripted adapter"; }

    bool open_should_fail_ = false;
    bool opened_ = false;
    bool closed_ = false;
    InboundHandler inbound_;
    std::vector<Packet> outbound_;
};

TEST_CASE("adapter contract: open, bidirectional delivery, close", "[platform][adapter]") {
    ScriptedAdapter adapter;
    REQUIRE_FALSE(adapter.is_open());
    CHECK_FALSE(adapter.write(Packet{0x45})); // closed before open: dropped

    std::atomic<int> inbound_count{0};
    Packet last_inbound;
    REQUIRE(adapter.open([&](Packet packet) {
        last_inbound = std::move(packet);
        ++inbound_count;
    }));
    REQUIRE(adapter.is_open());
    REQUIRE_FALSE(adapter.inbound_ == nullptr);

    // Core -> device.
    const Packet frame{0x45, 0x00, 0x00, 0x14, 0x01, 0x02};
    REQUIRE(adapter.write(frame));
    REQUIRE(adapter.outbound_.size() == 1);
    REQUIRE(adapter.outbound_[0] == frame);

    // Device -> core (reader-thread delivery, driven directly).
    adapter.inbound_(Packet{0x60});
    CHECK(inbound_count == 1);
    CHECK(last_inbound == Packet{0x60});

    // Close stops both directions.
    adapter.close();
    REQUIRE_FALSE(adapter.is_open());
    REQUIRE_FALSE(adapter.write(frame));
    CHECK(adapter.inbound_ == nullptr);
}

TEST_CASE("adapter contract: open failure is reported, never thrown", "[platform][adapter]") {
    ScriptedAdapter adapter;
    adapter.open_should_fail_ = true;
    REQUIRE_FALSE(adapter.open([](Packet) {}));
    REQUIRE_FALSE(adapter.is_open());
    // A failed open must leave the adapter safely closeable.
    adapter.close();
}

TEST_CASE("per-OS factory provides a usable, initially-closed adapter", "[platform][adapter]") {
    auto adapter = pqvpn::platform::make_adapter();
    REQUIRE(adapter != nullptr);
    // Construction must not touch any device; only open() may.
    REQUIRE_FALSE(adapter->is_open());
    CHECK_FALSE(adapter->describe().empty());
}
