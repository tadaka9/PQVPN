#include <catch2/catch_test_macros.hpp>
#include "node_module.hpp"
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

TEST_CASE("PQVPNNode::choose_relay logic", "[node][relay]") {
    pqvpn::PQVPNNode node("test_config.ini");

    std::vector<uint8_t> my_id = {0x01, 0x02};
    node.set_my_id(my_id);

    auto add_to_mesh = [&](const std::vector<uint8_t>& id, bool relay, const std::string& name) {
        std::stringstream ss;
        for(auto b : id) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        pqvpn::PQVPNNode::PeerInfo info;
        info.peer_id = id;
        info.is_relay = relay;
        info.nickname = name;
        node.mesh.peers[ss.str()] = info;
    };

    std::vector<uint8_t> p1_id = {0xAA, 0xBB};
    std::vector<uint8_t> p2_id = {0xCC, 0xDD};
    std::vector<uint8_t> dest_id = {0xEE, 0xFF};

    SECTION("Pick available relay") {
        add_to_mesh(p1_id, false, "p1");
        add_to_mesh(p2_id, true, "p2");
        add_to_mesh(dest_id, true, "p3");

        auto choice = node.choose_relay(p1_id);
        REQUIRE(choice.has_value());
        std::stringstream ss;
        for(auto b : *choice) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        // Order in map: "aabb" (p1), "ccdd" (p2), "eeff" (p3).
        // Dest is p1, so skip "aabb". Next is "ccdd" which is a relay.
        CHECK(ss.str() == "ccdd");
    }

    SECTION("Pick relay when destination is a relay") {
        add_to_mesh(p1_id, false, "p1");
        add_to_mesh(p2_id, true, "p2"); // Dest
        add_to_mesh(dest_id, true, "p3");

        auto choice = node.choose_relay(p2_id);
        REQUIRE(choice.has_value());
        std::stringstream ss;
        for(auto b : *choice) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        // Dest is p2, so skip "ccdd". Next is "eeff" which is a relay.
        CHECK(ss.str() == "eeff");
    }

    SECTION("Fallback to non-relay when no relays available") {
        add_to_mesh({0xAA, 0xBB}, false, "p1");
        add_to_mesh(dest_id, true, "p3"); // Dest is a relay

        auto choice = node.choose_relay(dest_id);
        REQUIRE(choice.has_value());
        std::stringstream ss;
        for(auto b : *choice) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        // Dest is p3 ("eeff"). Peer "aabb" is not a relay, but it's the only candidate.
        CHECK(ss.str() == "aabb");
    }

    SECTION("No candidates available") {
        node.mesh.peers.clear();
        add_to_mesh(p1_id, false, "p1"); // Dest is p1
        auto choice = node.choose_relay(p1_id);
        CHECK_FALSE(choice.has_value());
    }
}
