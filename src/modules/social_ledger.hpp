#pragma once

#include <cstdint>
#include <string>

#include "research_ledger.hpp"

namespace pqvpn::social {

enum class Achievement { DistrictDiscovered, CommunityHelp, VerifiedService };

inline const char* to_string(Achievement value) {
    switch (value) {
    case Achievement::DistrictDiscovered: return "district-discovered";
    case Achievement::CommunityHelp: return "community-help";
    case Achievement::VerifiedService: return "verified-service";
    }
    return "invalid";
}

struct Claim {
    std::string beneficiary;
    Achievement achievement = Achievement::DistrictDiscovered;
    std::string evidence_digest;
    std::uint64_t completed_at_ms = 0;
    std::uint64_t nonce = 0;
    research::HybridProof proof;
};

inline research::Bytes payload(const Claim& claim) {
    return research::encode({{"achievement", to_string(claim.achievement)},
        {"beneficiary", claim.beneficiary}, {"completed_at_ms", claim.completed_at_ms},
        {"domain", "PQVPN/strangenet-achievement/v1"},
        {"evidence_digest", claim.evidence_digest}, {"nonce", claim.nonce}});
}

inline bool valid(const Claim& claim, const research::PublicIdentity& identity) {
    return research::wallet_address(identity) == claim.beneficiary &&
        group_chat::valid_peer_id(claim.evidence_digest) && claim.completed_at_ms > 0 &&
        claim.nonce > 0 && research::verify(payload(claim), identity, claim.proof);
}

} // namespace pqvpn::social
