// Simple compilation and basic functionality test for save_known_peers
#include "src/modules/node_module.hpp"
#include <iostream>

int main() {
    pqvpn::PQVPNNode node("test_config.toml");
    node.save_known_peers();
    std::cout << "save_known_peers compiles successfully!" << std::endl;
    return 0;
}