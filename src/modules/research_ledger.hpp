#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "group_chat.hpp"
#include "hybrid_auth.hpp"

namespace pqvpn::research {

using Bytes = std::vector<std::uint8_t>;

struct PublicIdentity {
    Bytes ed25519;
    Bytes ml_dsa_87;
};

struct HybridProof {
    Bytes ed25519;
    Bytes ml_dsa_87;
};

struct SubnetPolicy {
    std::string id;
    std::string parent_id;
    std::string operator_name;
    std::string operator_peer_id;
    std::vector<std::string> rules;
    std::map<std::string, PublicIdentity> validators;
    std::uint64_t max_supply = 21'000'000;
    std::uint64_t reward_per_valid_result = 1;
    std::uint64_t epoch = 1;
    std::set<std::string> allowed_projects;
    bool transfers_enabled = true;
    std::size_t max_rewards_per_block = 1024;
    std::map<std::string, std::uint64_t> genesis_allocations;
};

struct PolicyVote {
    std::string validator;
    HybridProof proof;
};

struct ScientificAttestation {
    std::string subnet_id;
    std::string job_id;
    std::string result_digest;
    std::string beneficiary;
    std::string project;
    std::uint64_t completed_at_ms = 0;
    std::string validator;
    HybridProof proof;
};

struct Block {
    std::string subnet_id;
    std::uint64_t height = 0;
    std::uint64_t epoch = 0;
    std::string previous_hash;
    std::vector<ScientificAttestation> rewards;
    std::string proposer;
};

struct BlockVote {
    std::string validator;
    HybridProof proof;
};

struct FinalizedBlock {
    Block block;
    std::vector<BlockVote> certificate;
};

struct Wallet {
    PublicIdentity identity;
    std::string address;
};

struct GenesisManifest {
    std::string subnet_id;
    std::uint64_t max_supply = 0;
    std::vector<Wallet> wallets;
};

struct Transfer {
    std::string subnet_id;
    std::string from;
    std::string to;
    std::uint64_t amount = 0;
    std::uint64_t nonce = 0;
    HybridProof proof;
};

inline std::string hex(const Bytes& data) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string value;
    value.reserve(data.size() * 2);
    for (const auto byte : data) {
        value.push_back(digits[byte >> 4]);
        value.push_back(digits[byte & 0x0f]);
    }
    return value;
}

inline std::optional<Bytes> unhex(const std::string& value) {
    if (value.size() % 2) return std::nullopt;
    Bytes out; out.reserve(value.size() / 2);
    auto nibble=[](char c)->int { if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1; };
    for(std::size_t i=0;i<value.size();i+=2){const int a=nibble(value[i]),b=nibble(value[i+1]);if(a<0||b<0)return std::nullopt;out.push_back(static_cast<std::uint8_t>((a<<4)|b));}
    return out;
}

inline Bytes encode(const nlohmann::ordered_json& value) {
    const auto text = value.dump();
    return {text.begin(), text.end()};
}

inline std::string digest(const Bytes& payload) {
    const auto value = crypto::sha3_512(payload);
    return hex(Bytes(value.begin(), value.begin() + 32));
}

inline bool valid_identifier(const std::string& value, const std::size_t maximum = 128) {
    if (value.empty() || value.size() > maximum) return false;
    return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
        return std::isalnum(character) || character == '.' || character == '_' ||
            character == '-' || character == '/';
    });
}

inline std::size_t quorum(const std::size_t validators) {
    return validators == 0 ? std::numeric_limits<std::size_t>::max() :
        (2 * validators) / 3 + 1;
}

inline bool valid_policy(const SubnetPolicy& policy) {
    if (!valid_identifier(policy.id) || policy.id == policy.parent_id ||
        policy.operator_name.empty() || policy.operator_name.size() > 128 ||
        !group_chat::valid_peer_id(policy.operator_peer_id) ||
        policy.validators.empty() || policy.validators.size() > 128 ||
        policy.rules.size() > 64 || policy.max_supply == 0 ||
        policy.reward_per_valid_result == 0 || policy.epoch == 0 ||
        policy.max_rewards_per_block == 0 || policy.max_rewards_per_block > 4096) return false;
    if (!policy.parent_id.empty() &&
        (policy.id.size() <= policy.parent_id.size() ||
         policy.id.compare(0, policy.parent_id.size(), policy.parent_id) != 0 ||
         policy.id[policy.parent_id.size()] != '/')) return false;
    for (const auto& rule : policy.rules)
        if (rule.empty() || rule.size() > 256) return false;
    for (const auto& project : policy.allowed_projects)
        if (!valid_identifier(project, 192)) return false;
    std::uint64_t genesis_supply = 0;
    for (const auto& [address, amount] : policy.genesis_allocations) {
        if (!group_chat::valid_peer_id(address) || amount == 0 ||
            amount > policy.max_supply - genesis_supply) return false;
        genesis_supply += amount;
    }
    for (const auto& [name, identity] : policy.validators)
        if (!valid_identifier(name) || identity.ed25519.size() != 32 ||
            identity.ml_dsa_87.empty()) return false;
    return true;
}

inline Bytes policy_payload(const SubnetPolicy& policy) {
    nlohmann::ordered_json validators = nlohmann::ordered_json::array();
    for (const auto& [name, identity] : policy.validators)
        validators.push_back({{"ed25519", hex(identity.ed25519)},
                              {"id", name}, {"ml_dsa_87", hex(identity.ml_dsa_87)}});
    return encode({{"domain", "PQVPN/subnet-policy/v2"}, {"epoch", policy.epoch},
                   {"genesis_allocations", policy.genesis_allocations},
                   {"id", policy.id}, {"max_supply", policy.max_supply},
                   {"operator_name", policy.operator_name},
                   {"operator_peer_id", policy.operator_peer_id},
                   {"parent_id", policy.parent_id},
                   {"allowed_projects", policy.allowed_projects},
                   {"max_rewards_per_block", policy.max_rewards_per_block},
                   {"reward_per_valid_result", policy.reward_per_valid_result},
                   {"rules", policy.rules}, {"transfers_enabled", policy.transfers_enabled},
                   {"validators", validators}});
}

inline Bytes attestation_payload(const ScientificAttestation& claim) {
    return encode({{"beneficiary", claim.beneficiary},
                   {"completed_at_ms", claim.completed_at_ms},
                   {"domain", "PQVPN/scientific-attestation/v1"},
                   {"job_id", claim.job_id}, {"project", claim.project},
                   {"result_digest", claim.result_digest},
                   {"subnet_id", claim.subnet_id}, {"validator", claim.validator}});
}

inline Bytes block_payload(const Block& block) {
    nlohmann::ordered_json rewards = nlohmann::ordered_json::array();
    for (const auto& claim : block.rewards)
        rewards.push_back(digest(attestation_payload(claim)));
    return encode({{"domain", "PQVPN/research-block/v1"}, {"epoch", block.epoch},
                   {"height", block.height}, {"previous_hash", block.previous_hash},
                   {"proposer", block.proposer}, {"rewards", rewards},
                   {"subnet_id", block.subnet_id}});
}

inline std::string block_hash(const Block& block) { return digest(block_payload(block)); }

inline Bytes transfer_payload(const Transfer& transfer) {
    return encode({{"amount", transfer.amount}, {"domain", "PQVPN/transfer/v1"},
                   {"from", transfer.from}, {"nonce", transfer.nonce},
                   {"subnet_id", transfer.subnet_id}, {"to", transfer.to}});
}

inline HybridProof sign(const Bytes& payload, const Bytes& ed_private, const Bytes& pq_private) {
    const auto hashed = crypto::sha3_512(payload);
    return {crypto::ed25519_sign(ed_private, hashed), pq_sig_sign(pq_private, hashed)};
}

inline bool verify(const Bytes& payload, const PublicIdentity& identity, const HybridProof& proof) {
    const auto hashed = crypto::sha3_512(payload);
    return crypto::ed25519_verify(identity.ed25519, hashed, proof.ed25519) &&
        pq_sig_verify(identity.ml_dsa_87, hashed, proof.ml_dsa_87);
}

inline std::string wallet_address(const PublicIdentity& identity) {
    Bytes material{'P','Q','V','P','N','/','w','a','l','l','e','t','/','v','1'};
    material.insert(material.end(), identity.ed25519.begin(), identity.ed25519.end());
    material.insert(material.end(), identity.ml_dsa_87.begin(), identity.ml_dsa_87.end());
    return digest(material);
}

inline Bytes genesis_payload(const GenesisManifest& manifest) {
    auto ordered_wallets = manifest.wallets;
    std::sort(ordered_wallets.begin(), ordered_wallets.end(),
        [](const Wallet& left, const Wallet& right) { return left.address < right.address; });
    nlohmann::ordered_json wallets = nlohmann::ordered_json::array();
    for (const auto& wallet : ordered_wallets)
        wallets.push_back({{"address", wallet.address},
                           {"ed25519", hex(wallet.identity.ed25519)},
                           {"ml_dsa_87", hex(wallet.identity.ml_dsa_87)}});
    return encode({{"domain", "PQVPN/genesis/v1"}, {"max_supply", manifest.max_supply},
                   {"subnet_id", manifest.subnet_id}, {"wallets", wallets}});
}

inline std::string genesis_hash(const GenesisManifest& manifest) {
    return digest(genesis_payload(manifest));
}

inline bool verify_policy_authorization(const SubnetPolicy& child,
                                        const SubnetPolicy& parent,
                                        const std::vector<PolicyVote>& votes) {
    if (!valid_policy(child) || !valid_policy(parent) || child.parent_id != parent.id ||
        child.epoch < parent.epoch) return false;
    const auto payload = policy_payload(child);
    std::set<std::string> accepted;
    for (const auto& vote : votes) {
        const auto validator = parent.validators.find(vote.validator);
        if (validator != parent.validators.end() && accepted.insert(vote.validator).second &&
            verify(payload, validator->second, vote.proof)) continue;
        if (validator != parent.validators.end()) return false;
    }
    return accepted.size() >= quorum(parent.validators.size());
}

inline bool verify_attestation(const ScientificAttestation& claim,
                               const SubnetPolicy& policy) {
    const auto validator = policy.validators.find(claim.validator);
    return validator != policy.validators.end() && claim.subnet_id == policy.id &&
        valid_identifier(claim.job_id, 192) && valid_identifier(claim.project, 192) &&
        group_chat::valid_peer_id(claim.result_digest) &&
        group_chat::valid_peer_id(claim.beneficiary) && claim.completed_at_ms != 0 &&
        (policy.allowed_projects.empty() || policy.allowed_projects.contains(claim.project)) &&
        verify(attestation_payload(claim), validator->second, claim.proof);
}

class VoteGuard {
public:
    bool record(const std::string& subnet, const std::uint64_t height,
                const std::string& validator, const std::string& hash) {
        const auto key = subnet + "\n" + std::to_string(height) + "\n" + validator;
        const auto [it, inserted] = votes_.emplace(key, hash);
        return inserted || it->second == hash;
    }
private:
    std::unordered_map<std::string, std::string> votes_;
};

class Ledger {
public:
    explicit Ledger(SubnetPolicy policy) : policy_(std::move(policy)) {
        if (!valid_policy(policy_)) throw std::invalid_argument("invalid subnet policy");
    }

    const SubnetPolicy& policy() const { return policy_; }
    std::uint64_t height() const { return height_; }
    std::uint64_t supply() const { return supply_; }
    const std::string& head() const { return head_; }
    const std::string& genesis() const { return genesis_hash_; }
    std::uint64_t balance(const std::string& address) const {
        const auto found = balances_.find(address);
        return found == balances_.end() ? 0 : found->second;
    }

    nlohmann::ordered_json audit_snapshot() const {
        std::map<std::string, std::uint64_t> ordered_balances(
            balances_.begin(), balances_.end());
        return {{"balances", ordered_balances}, {"genesis_hash", genesis_hash_},
                {"genesis_supply", genesis_supply_}, {"head", head_}, {"height", height_},
                {"max_supply", policy_.max_supply},
                {"policy_digest", digest(policy_payload(policy_))},
                {"subnet_id", policy_.id}, {"supply", supply_},
                {"version", 2}};
    }

    nlohmann::ordered_json checkpoint() const {
        nlohmann::ordered_json wallets=nlohmann::ordered_json::object();
        for(const auto& [address,identity]:wallets_) wallets[address]={{"ed25519",hex(identity.ed25519)},{"ml_dsa_87",hex(identity.ml_dsa_87)}};
        nlohmann::ordered_json value={{"balances",balances_},{"genesis_hash",genesis_hash_},
            {"genesis_supply",genesis_supply_},{"head",head_},{"height",height_},{"nonces",nonces_},
            {"policy_digest",digest(policy_payload(policy_))},{"seen_jobs",seen_jobs_},{"subnet_id",policy_.id},
            {"supply",supply_},{"version",2},{"wallets",wallets}};
        value["checksum"]=digest(encode(value)); return value;
    }

    static std::optional<Ledger> recover(const SubnetPolicy& policy,const nlohmann::ordered_json& source){
        try {
            auto value=source;const auto checksum=value.at("checksum").get<std::string>();value.erase("checksum");
            const auto version=value.at("version").get<int>();
            if(checksum!=digest(encode(value))||(version!=1&&version!=2)||value.at("subnet_id")!=policy.id||
               value.at("policy_digest")!=digest(policy_payload(policy)))return std::nullopt;
            Ledger ledger(policy);ledger.head_=value.at("head").get<std::string>();ledger.height_=value.at("height").get<std::uint64_t>();
            ledger.supply_=value.at("supply").get<std::uint64_t>();ledger.balances_=value.at("balances").get<decltype(ledger.balances_)>();
            ledger.nonces_=value.at("nonces").get<decltype(ledger.nonces_)>();ledger.seen_jobs_=value.at("seen_jobs").get<decltype(ledger.seen_jobs_)>();
            if(version==2){ledger.genesis_hash_=value.at("genesis_hash").get<std::string>();ledger.genesis_supply_=value.at("genesis_supply").get<std::uint64_t>();}
            for(const auto& [address,item]:value.at("wallets").items()){auto ed=unhex(item.at("ed25519")),pq=unhex(item.at("ml_dsa_87"));if(!ed||!pq)return std::nullopt;ledger.wallets_[address]={*ed,*pq};}
            if(ledger.height_>0||!ledger.genesis_hash_.empty())ledger.finalized_hashes_.insert(ledger.head_);
            if(!group_chat::valid_peer_id(ledger.head_)||!ledger.verify_invariants())return std::nullopt;
            return ledger;
        }catch(...){return std::nullopt;}
    }

    bool verify_invariants() const {
        std::uint64_t total = 0;
        for (const auto& [address, value] : balances_) {
            if (!wallets_.contains(address) || value > policy_.max_supply - total)
                return false;
            total += value;
        }
        const bool pristine = genesis_hash_.empty() && genesis_supply_ == 0;
        return total == supply_ && supply_ <= policy_.max_supply &&
            genesis_supply_ <= supply_ &&
            (pristine ? policy_.genesis_allocations.empty() &&
                        (height_ != 0 || head_ == std::string(64, '0'))
                      : group_chat::valid_peer_id(genesis_hash_)) &&
            (height_ == 0 && pristine ? head_ == std::string(64, '0') :
                                        finalized_hashes_.contains(head_));
    }

    bool register_wallet(const Wallet& wallet) {
        return group_chat::valid_peer_id(wallet.address) &&
            wallet.address == wallet_address(wallet.identity) &&
            wallets_.emplace(wallet.address, wallet.identity).second;
    }

    bool initialize_genesis(const GenesisManifest& manifest) {
        if (height_ != 0 || supply_ != 0 || !genesis_hash_.empty() ||
            head_ != std::string(64, '0') || !wallets_.empty() ||
            policy_.genesis_allocations.empty() || manifest.subnet_id != policy_.id ||
            manifest.max_supply != policy_.max_supply ||
            manifest.wallets.size() != policy_.genesis_allocations.size()) return false;
        std::unordered_map<std::string, PublicIdentity> wallets;
        for (const auto& wallet : manifest.wallets) {
            if (!group_chat::valid_peer_id(wallet.address) ||
                wallet.identity.ed25519.size() != 32 || wallet.identity.ml_dsa_87.empty() ||
                wallet.address != wallet_address(wallet.identity) ||
                !policy_.genesis_allocations.contains(wallet.address) ||
                !wallets.emplace(wallet.address, wallet.identity).second) return false;
        }
        std::uint64_t total = 0;
        for (const auto& [address, amount] : policy_.genesis_allocations) {
            if (!wallets.contains(address) || amount > policy_.max_supply - total) return false;
            total += amount;
        }
        wallets_ = std::move(wallets);
        balances_.insert(policy_.genesis_allocations.begin(), policy_.genesis_allocations.end());
        supply_ = total;
        genesis_supply_ = total;
        genesis_hash_ = genesis_hash(manifest);
        head_ = genesis_hash_;
        finalized_hashes_.insert(head_);
        return verify_invariants();
    }

    bool finalize(const FinalizedBlock& finalized) {
        const auto& block = finalized.block;
        if ((!policy_.genesis_allocations.empty() && genesis_hash_.empty()) ||
            block.subnet_id != policy_.id || block.epoch != policy_.epoch ||
            block.height != height_ + 1 || block.previous_hash != head_ ||
            block.rewards.empty() || block.rewards.size() > policy_.max_rewards_per_block ||
            policy_.validators.find(block.proposer) == policy_.validators.end()) return false;
        const auto hash = block_hash(block);
        std::set<std::string> voters;
        for (const auto& vote : finalized.certificate) {
            const auto validator = policy_.validators.find(vote.validator);
            if (validator == policy_.validators.end() || !voters.insert(vote.validator).second ||
                !verify(block_payload(block), validator->second, vote.proof)) return false;
        }
        if (voters.size() < quorum(policy_.validators.size())) return false;
        std::unordered_set<std::string> jobs;
        for (const auto& claim : block.rewards) {
            if (!verify_attestation(claim, policy_) ||
                !jobs.insert(claim.job_id).second || seen_jobs_.contains(claim.job_id) ||
                !wallets_.contains(claim.beneficiary)) return false;
        }
        const auto amount = policy_.reward_per_valid_result * block.rewards.size();
        if (policy_.reward_per_valid_result != 0 &&
            amount / policy_.reward_per_valid_result != block.rewards.size()) return false;
        if (amount > policy_.max_supply - supply_) return false;
        for (const auto& claim : block.rewards) {
            const auto current = balances_[claim.beneficiary];
            if (current > std::numeric_limits<std::uint64_t>::max() -
                          policy_.reward_per_valid_result) return false;
            balances_[claim.beneficiary] = current + policy_.reward_per_valid_result;
            seen_jobs_.insert(claim.job_id);
        }
        supply_ += amount;
        height_ = block.height;
        head_ = hash;
        finalized_hashes_.insert(hash);
        return verify_invariants();
    }

    bool transfer(const Transfer& transfer) {
        if (!policy_.transfers_enabled || transfer.subnet_id != policy_.id || transfer.amount == 0 ||
            transfer.from == transfer.to || !wallets_.contains(transfer.from) ||
            !wallets_.contains(transfer.to) ||
            transfer.nonce != nonces_[transfer.from] + 1 ||
            balances_[transfer.from] < transfer.amount ||
            !verify(transfer_payload(transfer), wallets_.at(transfer.from), transfer.proof) ||
            balances_[transfer.to] > std::numeric_limits<std::uint64_t>::max() - transfer.amount)
            return false;
        balances_[transfer.from] -= transfer.amount;
        balances_[transfer.to] += transfer.amount;
        nonces_[transfer.from] = transfer.nonce;
        return verify_invariants();
    }

private:
    SubnetPolicy policy_;
    std::uint64_t height_ = 0;
    std::uint64_t supply_ = 0;
    std::uint64_t genesis_supply_ = 0;
    std::string head_ = std::string(64, '0');
    std::string genesis_hash_;
    std::unordered_map<std::string, PublicIdentity> wallets_;
    std::unordered_map<std::string, std::uint64_t> balances_;
    std::unordered_map<std::string, std::uint64_t> nonces_;
    std::unordered_set<std::string> seen_jobs_;
    std::unordered_set<std::string> finalized_hashes_;
};

} // namespace pqvpn::research
