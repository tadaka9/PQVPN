#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "group_chat.hpp"
#include "hybrid_auth.hpp"

namespace pqvpn::identity_claim {

enum class Category { Organization, NationalParty, PublicFigure };

struct Claim {
    std::string subject_peer;
    std::string display_name;
    Category category = Category::Organization;
    std::string issuer;
    std::string evidence_uri;
    std::uint64_t issued_at_ms = 0;
    std::uint64_t expires_at_ms = 0;
    std::vector<std::uint8_t> ed25519_signature;
    std::vector<std::uint8_t> ml_dsa_signature;
};

struct TrustedIssuer {
    std::vector<std::uint8_t> ed25519_public_key;
    std::vector<std::uint8_t> ml_dsa_public_key;
};

inline std::string category_name(const Category category) {
    switch (category) {
        case Category::NationalParty: return "national-party";
        case Category::PublicFigure: return "public-figure";
        default: return "organization";
    }
}

inline std::vector<std::uint8_t> canonical_payload(const Claim& claim) {
    const nlohmann::ordered_json value = {
        {"category", category_name(claim.category)},
        {"display_name", claim.display_name},
        {"evidence_uri", claim.evidence_uri},
        {"expires_at_ms", claim.expires_at_ms},
        {"issued_at_ms", claim.issued_at_ms},
        {"issuer", claim.issuer},
        {"subject_peer", claim.subject_peer},
        {"version", 1},
    };
    const auto encoded = value.dump();
    return {encoded.begin(), encoded.end()};
}

// Verification is deliberately local-policy based. A cryptographically valid
// badge is accepted only when its issuer and public keys were explicitly added
// to the user's trust store. It conveys identity, never message access.
inline bool verify(
    const Claim& claim,
    const std::unordered_map<std::string, TrustedIssuer>& trust_store,
    const std::uint64_t now_ms) {
    const auto issuer = trust_store.find(claim.issuer);
    if (issuer == trust_store.end() || !group_chat::valid_peer_id(claim.subject_peer) ||
        claim.display_name.empty() || claim.display_name.size() > 96 ||
        claim.issuer.empty() || claim.issuer.size() > 128 ||
        claim.evidence_uri.size() > 512 || claim.issued_at_ms == 0 ||
        claim.expires_at_ms <= claim.issued_at_ms || now_ms < claim.issued_at_ms ||
        now_ms >= claim.expires_at_ms) return false;
    const auto payload = canonical_payload(claim);
    return crypto::ed25519_verify(
               issuer->second.ed25519_public_key, payload, claim.ed25519_signature) &&
        pq_sig_verify(issuer->second.ml_dsa_public_key, payload, claim.ml_dsa_signature);
}

} // namespace pqvpn::identity_claim
