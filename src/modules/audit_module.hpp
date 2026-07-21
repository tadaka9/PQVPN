#ifndef AUDIT_MODULE_HPP
#define AUDIT_MODULE_HPP

#include <string>
#include <vector>
#include <deque>
#include <cstdint>
#include <chrono>
#include <spdlog/spdlog.h>

struct AuditLogEntry {
    double timestamp;
    std::string event_type;
    std::vector<uint8_t> peer_id;
    std::string description;
    std::vector<uint8_t> hash_chain;
};

class AuditTrail {
public:
    AuditTrail();

    void log_event(const std::string& event_type,
                   const std::vector<uint8_t>& peer_id,
                   const std::string& description);

    bool verify_integrity() const;

private:
    std::vector<AuditLogEntry> entries;
    std::deque<std::vector<uint8_t>> merkle_hashes;
    std::vector<uint8_t> last_hash;

    static constexpr size_t MAX_HASHES = 1440;
};

#endif // AUDIT_MODULE_HPP
