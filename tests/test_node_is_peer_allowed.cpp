#include <iostream>
#include <vector>
#include <cassert>
#include "node_module.hpp"

int main() {
    asio::io_context io_context;
    pqvpn::PQVPNNode node(io_context);

    std::vector<uint8_t> my_id = {0xDE, 0xAD, 0xBE, 0xEF};
    node.set_my_id(my_id);

    std::vector<uint8_t> peer_id = {0xCA, 0xFE, 0xBA, 0xBE};

    // Test Case 1: session_salt - my_id is set
    auto salt1 = node.session_salt(peer_id);
    assert(salt1.size() == 16);

    // Test Case 2: session_salt - my_id is empty (proxy for None)
    node.set_my_id({});
    auto salt2 = node.session_salt(peer_id);
    assert(salt2.size() == 16);

    // Test Case 3: session_salt - deterministic output
    std::vector<uint8_t> peer_id_fixed = {0x01, 0x02};
    node.set_my_id({0x03, 0x04});

    auto salt3 = node.session_salt(peer_id_fixed);
    assert(!salt3.empty());
    auto salt3_retry = node.session_salt(peer_id_fixed);
    assert(salt3 == salt3_retry);

    // Test Case 4: is_peer_allowed - TOFU enabled by default
    assert(node.is_peer_allowed({0x12, 0x34}) == true);

    // Test Case 5: is_peer_allowed - TOFU disabled, no known peer
    node.set_tofu_enabled(false);
    assert(node.is_peer_allowed({0x12, 0x34}) == false);

    // Test Case 6: is_peer_allowed - Known peer
    std::vector<uint8_t> known_peer_bytes = {0x12, 0x34, 0xAB, 0xCD};
    node.add_known_peer(known_peer_bytes);
    assert(node.is_peer_allowed(known_peer_bytes) == true);

    // Test Case 7: is_peer_allowed - Allowlist
    node.set_allowlist({"aabbccdd"});
    assert(node.is_peer_allowed({0xAA, 0xBB, 0xCC, 0xDD}) == true);
    assert(node.is_peer_allowed({0x11, 0x22, 0x33, 0x44}) == false);

    std::cout << "Session salt and peer allowed tests passed!" << std::endl;
    return 0;
}
