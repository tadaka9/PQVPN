#include "traffic_obfuscation.hpp"
#include <vector>
#include <cstdint>
#include <iostream>
#include <cassert>

void test_init_defaults() {
    TrafficObfuscation tob;
    // Check if we can call choose_bucket with defaults
    size_t bucket = tob.choose_bucket(100);
    assert(bucket == 128);
    std::cout << "test_init_defaults passed" << std::endl;
}

void test_init_custom() {
    TrafficObfuscation::Config cfg;
    cfg.padding_buckets = {500, 1000};
    TrafficObfuscation tob(cfg);

    assert(tob.choose_bucket(100) == 500);
    assert(tob.choose_bucket(600) == 1000);
    assert(tob.choose_bucket(2000) == 2048); // Round up to the next 256-byte boundary
    std::cout << "test_init_custom passed" << std::endl;
}

void test_padding_logic() {
    TrafficObfuscation tob;
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    auto obfuscated = tob.compress_payload(data);

    // Header is 3 bytes (1 flag + 2 len)
    // Payload should be at least 128 bytes due to first bucket
    assert(obfuscated.size() >= 128);

    auto deobfuscated = tob.decompress_payload(obfuscated);
    // Should contain the original data
    assert(deobfuscated.size() >= 4);
    assert(deobfuscated[0] == 0xDE);
    assert(deobfuscated[3] == 0xEF);

    std::cout << "test_padding_logic passed" << std::endl;
}

int main() {
    try {
        test_init_defaults();
        test_init_custom();
        test_padding_logic();
        std::cout << "All TrafficObfuscation tests passed!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
