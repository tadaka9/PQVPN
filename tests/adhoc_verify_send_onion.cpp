
#include <iostream>
#include <vector>
#include <cassert>
#include "src/modules/node_module.hpp"

int main() {
    try {
        pqvpn::PQVPNNode node("test_config.toml");

        std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
        std::vector<uint8_t> next_hop_hash = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        uint32_t circuit_id = 0x12345678;
        uint8_t frame_type = 0x01; // FT_RELAY

        std::vector<uint8_t> frame = node.make_outer_frame(frame_type, next_hop_hash, circuit_id, payload);

        // Expected structure:
        // [0] version (1)
        // [1] type (0x01)
        // [2-9] hash (01 02 03 04 05 06 07 08)
        // [10-13] circuit_id (12 34 56 78)
        // [14-15] length (00 DE) - wait, payload size is 4. length is 0x0004.
        // [16...] payload

        assert(frame.size() == 16 + payload.size());
        assert(frame[0] == 1);
        assert(frame[1] == 0x01);
        assert(frame[2] == 0x01 && frame[9] == 0x08);
        assert(frame[10] == 0x12 && frame[13] == 0x78);
        assert(frame[14] == 0x00 && frame[15] == 0x04);
        assert(frame[16] == 0xDE && frame[19] == 0xEF);

        std::cout << "Ad-hoc verification PASSED: make_outer_frame correctly constructed the packet." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ad-hoc verification FAILED: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
