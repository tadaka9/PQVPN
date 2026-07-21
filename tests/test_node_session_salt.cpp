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

    // Test Case 1: my_id is set, a <= b (assuming comparison works on vectors)
    // my_id = {DE, AD, BE, EF}, peer_id = {CA, FE, BA, BE}
    // DE < CA is false. So it should go to 'else' (b + a)
    auto salt1 = node.session_salt(peer_id);
    assert(salt1.size() == 16);

    // Test Case 2: an empty identity models an absent node identity.
    node.set_my_id({});
    auto salt2 = node.session_salt(peer_id);
    assert(salt2.size() == 16);

    // Test Case 3: Verify deterministic output with known vector
    std::vector<uint8_t> peer_id_fixed = {0x01, 0x02};
    node.set_my_id({0x03, 0x04});
    auto salt3 = node.session_salt(peer_id_fixed);
    assert(!salt3.empty());
    auto salt3_retry = node.session_salt(peer_id_fixed);
    assert(salt3 == salt3_retry);

    std::cout << "Session salt tests passed!" << std::endl;
    return 0;
}
