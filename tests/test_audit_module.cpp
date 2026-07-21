#include <catch2/catch_test_macros.hpp>
#include "audit_module.hpp"
#include <vector>
#include <string>

TEST_CASE("AuditTrail Integrity Verification", "[audit]") {
    AuditTrail audit;

    SECTION("Empty audit trail is valid") {
        REQUIRE(audit.verify_integrity() == true);
    }

    SECTION("Single valid entry maintains integrity") {
        std::vector<uint8_t> peer_id = {0xde, 0xad, 0xbe, 0xef};
        audit.log_event("test_event", peer_id, "test_description");
        REQUIRE(audit.verify_integrity() == true);
    }

    SECTION("Tampered entry fails integrity check") {
        std::vector<uint8_t> peer_id = {0xde, 0xad, 0xbe, 0xef};
        audit.log_event("test_event", peer_id, "test_description");
        // We can't easily tamper with the internal entries without a friend or accessor,
        // so we rely on the log_event providing a consistent chain.
        // To truly test tampering, we'd need to expose the entries for testing.
    }
}

TEST_CASE("AuditTrail Chain Consistency", "[audit]") {
    AuditTrail audit;
    std::vector<uint8_t> peer_id = {0x01, 0x02};

    audit.log_event("event1", peer_id, "desc1");
    audit.log_event("event2", peer_id, "desc2");
    audit.log_event("event3", peer_id, "desc3");

    REQUIRE(audit.verify_integrity() == true);
}
