// src/modules/traffic_obfuscation.hpp

#pragma once

#include <vector>
#include <cstdint>
#include <optional>
#include <map>
#include <algorithm>
#include <random>
#include <stdexcept>
#include <openssl/rand.h>

/**
 * @brief Advanced Traffic Obfuscation and DPI Evasion.
 *
 * Ported from main.py:1674-1740
 */
class TrafficObfuscation {
public:
    struct Config {
        bool decoy_enabled = true;
        int jitter_range = 50;
        double compression_ratio = 0.7;
        bool compression_enabled = false;
        std::vector<size_t> padding_buckets = {128, 256, 512, 1024, 1500};
    };

    explicit TrafficObfuscation(std::optional<Config> cfg = std::nullopt)
        : config_(cfg.value_or(Config{})) {}

    /**
     * @brief Choose the smallest bucket that fits the given length.
     */
    size_t choose_bucket(size_t length) const {
        for (size_t b : config_.padding_buckets) {
            if (length <= b) {
                return b;
            }
        }
        // If none matched, round up to the next 256 boundary to avoid leaking oversized lengths
        size_t next_bucket = ((length + 255) / 256) * 256;
        return std::min(next_bucket, static_cast<size_t>(65535));
    }

    /**
     * @brief Compress and pad payload for obfuscation.
     * Compression is rejected until a bounded decompressor is available.
     */
    std::vector<uint8_t> compress_payload(const std::vector<uint8_t>& data) {
        uint8_t flags = 0;
        std::vector<uint8_t> body = data;

        if (config_.compression_enabled) {
            throw std::logic_error("compression_enabled requires a bounded compression provider");
        }

        uint16_t orig_len = static_cast<uint16_t>(data.size());
        std::vector<uint8_t> payload;
        payload.reserve(body.size() + 3 + 1500); // Pre-allocate for header and padding

        // Header: [flags (1 byte)] + [orig_len (2 bytes, big-endian)]
        payload.push_back(flags);
        payload.push_back(static_cast<uint8_t>(orig_len >> 8));
        payload.push_back(static_cast<uint8_t>(orig_len & 0xFF));

        // Body
        payload.insert(payload.end(), body.begin(), body.end());

        size_t target = choose_bucket(payload.size());
        if (payload.size() < target) {
            const auto prior_size = payload.size();
            payload.resize(target);
            if (RAND_bytes(payload.data() + prior_size, static_cast<int>(target - prior_size)) != 1) {
                throw std::runtime_error("secure padding generation failed");
            }
        } else if (payload.size() > target) {
             // As per Python logic: ensure we still pad to obscure size (round-up strategy)
             size_t new_target = ((payload.size() + 255) / 256) * 256;
             new_target = std::min(new_target, static_cast<size_t>(65535));
             if (new_target > payload.size()) {
                 // This part of the Python logic is slightly redundant but preserved.
                 // If new_target > current size, we would need to expand.
                 // Since target was already >= payload.size(), this branch is unlikely
                 // unless the rounding logic changes.
             }
        }

        return payload;
    }

    /**
     * @brief Reverse compress_payload: remove padding and decompress if needed.
     */
    std::vector<uint8_t> decompress_payload(const std::vector<uint8_t>& data) {
        if (data.size() < 3) {
            return {};
        }

        uint8_t flags = data[0];
        uint16_t orig_len = (static_cast<uint16_t>(data[1]) << 8) | static_cast<uint16_t>(data[2]);

        size_t body_end = std::min(data.size(), static_cast<size_t>(3 + orig_len));
        std::vector<uint8_t> body(data.begin() + 3, data.begin() + body_end);

        if (flags == 0x01) {
            throw std::invalid_argument("compressed payloads are unsupported");
        }
        if (flags != 0) {
            throw std::invalid_argument("unknown traffic-obfuscation flags");
        }

        return body;
    }

private:
    Config config_;
};
