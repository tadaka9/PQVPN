#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "research_ledger.hpp"

namespace pqvpn::research::mesh {

enum class Kind { Proposal, Vote, Certificate, CatchupRequest, CatchupResponse, Attestation };

struct Envelope {
    Kind kind = Kind::Proposal;
    std::string subnet_id;
    std::string sender;
    std::uint64_t sequence = 0;
    std::uint64_t epoch = 0;
    nlohmann::ordered_json body;
    HybridProof proof;
};

inline std::string kind_name(Kind kind) {
    switch (kind) {
        case Kind::Vote: return "vote";
        case Kind::Certificate: return "certificate";
        case Kind::CatchupRequest: return "catchup-request";
        case Kind::CatchupResponse: return "catchup-response";
        case Kind::Attestation: return "attestation";
        default: return "proposal";
    }
}

inline Bytes payload(const Envelope& message) {
    return encode({{"body", message.body}, {"domain", "PQVPN/research-mesh/v1"},
                   {"epoch", message.epoch}, {"kind", kind_name(message.kind)},
                   {"sender", message.sender}, {"sequence", message.sequence},
                   {"subnet_id", message.subnet_id}});
}

inline bool verify_envelope(const Envelope& message, const SubnetPolicy& policy) {
    const auto sender = policy.validators.find(message.sender);
    if (sender == policy.validators.end() || message.subnet_id != policy.id ||
        message.epoch != policy.epoch || message.sequence == 0 ||
        message.body.dump().size() > 1024 * 1024) return false;
    return verify(payload(message), sender->second, message.proof);
}

class ReplayGuard {
public:
    bool accept(const Envelope& message) {
        const auto key = message.subnet_id + "\n" + message.sender;
        auto& last = last_[key];
        if (message.sequence <= last) return false;
        last = message.sequence;
        return true;
    }
private:
    std::unordered_map<std::string, std::uint64_t> last_;
};

inline bool accepts_during_partition(Kind kind) {
    return kind == Kind::CatchupRequest || kind == Kind::CatchupResponse;
}

} // namespace pqvpn::research::mesh
