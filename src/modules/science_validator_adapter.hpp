#pragma once
#include <optional>
#include <string>
#include <unordered_map>
#include "research_ledger.hpp"

namespace pqvpn::research {
struct ProjectReceipt {
    std::string project;std::string subnet_id;std::string job_id;std::string result_digest;
    std::string beneficiary;std::string outcome;std::uint64_t completed_at_ms=0;
    HybridProof project_proof;
};
inline Bytes project_receipt_payload(const ProjectReceipt& r){return encode({{"beneficiary",r.beneficiary},{"completed_at_ms",r.completed_at_ms},{"domain","PQVPN/project-validator-receipt/v1"},{"job_id",r.job_id},{"outcome",r.outcome},{"project",r.project},{"result_digest",r.result_digest},{"subnet_id",r.subnet_id}});}
class ProjectAdapter {
public:
 explicit ProjectAdapter(std::unordered_map<std::string,PublicIdentity> authorities):authorities_(std::move(authorities)){}
 std::optional<ScientificAttestation> ingest(const ProjectReceipt& receipt,const std::string& validator,
     const Bytes& validator_ed_private,const Bytes& validator_pq_private) const {
   const auto authority=authorities_.find(receipt.project);
   if(authority==authorities_.end()||receipt.outcome!="valid"||receipt.completed_at_ms==0||
      !group_chat::valid_peer_id(receipt.result_digest)||!group_chat::valid_peer_id(receipt.beneficiary)||
      !verify(project_receipt_payload(receipt),authority->second,receipt.project_proof))return std::nullopt;
   ScientificAttestation claim{receipt.subnet_id,receipt.job_id,receipt.result_digest,receipt.beneficiary,
      receipt.project,receipt.completed_at_ms,validator,{}};
   claim.proof=sign(attestation_payload(claim),validator_ed_private,validator_pq_private);return claim;
 }
private:std::unordered_map<std::string,PublicIdentity> authorities_;
};
}
