#pragma once

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "research_ledger.hpp"

namespace pqvpn::commons {

enum class ContributionKind { ScientificResult, CommunityValidation, ModerationAppeal };

inline const char* to_string(ContributionKind kind) {
    switch (kind) {
    case ContributionKind::ScientificResult: return "scientific-result";
    case ContributionKind::CommunityValidation: return "community-validation";
    case ContributionKind::ModerationAppeal: return "moderation-appeal";
    }
    return "invalid";
}

struct Contribution {
    ContributionKind kind = ContributionKind::ScientificResult;
    std::string beneficiary;
    std::string evidence_digest;
    std::string project;
    std::uint64_t completed_at_ms = 0;
    std::vector<std::string> confirmation_digests;
    std::string validator;
    research::HybridProof proof;
};

inline research::Bytes payload(const Contribution& value) {
    return research::encode({{"beneficiary", value.beneficiary},
        {"completed_at_ms", value.completed_at_ms},
        {"domain", "PQVPN/research-commons-contribution/v1"},
        {"evidence_digest", value.evidence_digest},
        {"confirmation_digests", value.confirmation_digests},
        {"kind", to_string(value.kind)}, {"project", value.project},
        {"validator", value.validator}});
}

inline bool reward_eligible(const Contribution& value,
                            const research::SubnetPolicy& policy) {
    const auto validator = policy.validators.find(value.validator);
    const bool useful_kind = value.kind == ContributionKind::ScientificResult ||
        value.kind == ContributionKind::CommunityValidation ||
        value.kind == ContributionKind::ModerationAppeal;
    const std::set<std::string> confirmations(value.confirmation_digests.begin(),
                                               value.confirmation_digests.end());
    const bool independent = confirmations.size() >= 2 && confirmations.size() <= 16 &&
        std::all_of(confirmations.begin(), confirmations.end(), group_chat::valid_peer_id);
    return useful_kind && independent && validator != policy.validators.end() &&
        research::valid_identifier(value.project, 192) &&
        (policy.allowed_projects.empty() || policy.allowed_projects.contains(value.project)) &&
        group_chat::valid_peer_id(value.beneficiary) &&
        group_chat::valid_peer_id(value.evidence_digest) &&
        value.completed_at_ms > 0 &&
        research::verify(payload(value), validator->second, value.proof);
}

inline std::optional<research::ScientificAttestation> to_attestation(
    const Contribution& value, const research::SubnetPolicy& policy,
    const research::Bytes& validator_ed_private,
    const research::Bytes& validator_pq_private) {
    if (!reward_eligible(value, policy)) return std::nullopt;
    research::ScientificAttestation result{policy.id,
        research::digest(payload(value)), value.evidence_digest, value.beneficiary,
        value.project, value.completed_at_ms, value.validator, {}};
    result.proof = research::sign(research::attestation_payload(result),
        validator_ed_private, validator_pq_private);
    return result;
}

} // namespace pqvpn::commons
