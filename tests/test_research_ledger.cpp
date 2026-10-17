#include <catch2/catch_test_macros.hpp>

#include "crypto_utils.hpp"
#include "research_ledger.hpp"
#include "research_store.hpp"
#include <chrono>
#include <fstream>

namespace {
struct Keys {
    pqvpn::crypto::Ed25519KeyPair ed = pqvpn::crypto::ed25519_keygen();
    pqvpn::SigKeyPair pq = pqvpn::pq_sig_keygen();
    pqvpn::research::PublicIdentity public_identity() const { return {ed.public_key, pq.public_key}; }
};

pqvpn::research::SubnetPolicy policy(const std::string& id,
                                     const std::string& parent,
                                     const std::vector<Keys>& validators) {
    pqvpn::research::SubnetPolicy value{id, parent, "Physical operator", std::string(64, 'a'),
        {"science-only", "one-pq-per-valid-result"}, {}, 21'000'000, 1, 1};
    for (std::size_t index = 0; index < validators.size(); ++index)
        value.validators.emplace("validator-" + std::to_string(index), validators[index].public_identity());
    value.allowed_projects = {"einstein-at-home", "primegrid"};
    return value;
}
}

TEST_CASE("mainnet authorizes a child subnet and its physical operator", "[research][subnet]") {
    const std::vector<Keys> validators(4);
    const auto mainnet = policy("mainnet", "", validators);
    const auto child = policy("mainnet/research-eu", "mainnet", validators);
    std::vector<pqvpn::research::PolicyVote> votes;
    for (std::size_t index = 0; index < 3; ++index)
        votes.push_back({"validator-" + std::to_string(index),
            pqvpn::research::sign(pqvpn::research::policy_payload(child),
                                  validators[index].ed.private_key, validators[index].pq.secret_key)});
    CHECK(pqvpn::research::verify_policy_authorization(child, mainnet, votes));
    votes.pop_back();
    CHECK_FALSE(pqvpn::research::verify_policy_authorization(child, mainnet, votes));
}

TEST_CASE("scientific rewards need attestation and deterministic quorum finality", "[research][consensus]") {
    const std::vector<Keys> validators(4);
    const auto subnet = policy("mainnet/research", "mainnet", validators);
    pqvpn::research::Ledger ledger(subnet);
    const Keys owner;
    const pqvpn::research::Wallet wallet{owner.public_identity(),
        pqvpn::research::wallet_address(owner.public_identity())};
    REQUIRE(ledger.register_wallet(wallet));
    pqvpn::research::ScientificAttestation claim{subnet.id, "job-0001", std::string(64, 'b'),
        wallet.address, "einstein-at-home", 1'700'000'000'000ULL, "validator-0", {}};
    claim.proof = pqvpn::research::sign(pqvpn::research::attestation_payload(claim),
                                       validators[0].ed.private_key, validators[0].pq.secret_key);
    pqvpn::research::Block block{subnet.id, 1, subnet.epoch, std::string(64, '0'), {claim}, "validator-0"};
    pqvpn::research::FinalizedBlock finalized{block, {}};
    for (std::size_t index = 0; index < 3; ++index)
        finalized.certificate.push_back({"validator-" + std::to_string(index),
            pqvpn::research::sign(pqvpn::research::block_payload(block),
                                  validators[index].ed.private_key, validators[index].pq.secret_key)});
    REQUIRE(ledger.finalize(finalized));
    CHECK(ledger.height() == 1);
    CHECK(ledger.supply() == 1);
    CHECK(ledger.balance(wallet.address) == 1);
    CHECK(ledger.verify_invariants());
    const auto audit = ledger.audit_snapshot();
    CHECK(audit.at("supply") == 1);
    CHECK(audit.at("height") == 1);
    CHECK(audit.at("policy_digest").get<std::string>().size() == 64);
    CHECK_FALSE(ledger.finalize(finalized)); // height/job replay and fork fail closed
    const auto recovered=pqvpn::research::Ledger::recover(subnet,ledger.checkpoint());
    REQUIRE(recovered);CHECK(recovered->height()==1);CHECK(recovered->balance(wallet.address)==1);
    auto corrupt=ledger.checkpoint();corrupt["supply"]=999;CHECK_FALSE(pqvpn::research::Ledger::recover(subnet,corrupt));
}

TEST_CASE("wallet transfers require hybrid signature balance and monotonic nonce", "[research][wallet]") {
    const std::vector<Keys> validators(1);
    const auto subnet = policy("mainnet/research", "mainnet", validators);
    pqvpn::research::Ledger ledger(subnet);
    const Keys sender, recipient;
    const pqvpn::research::Wallet from{sender.public_identity(), pqvpn::research::wallet_address(sender.public_identity())};
    const pqvpn::research::Wallet to{recipient.public_identity(), pqvpn::research::wallet_address(recipient.public_identity())};
    REQUIRE(ledger.register_wallet(from)); REQUIRE(ledger.register_wallet(to));
    pqvpn::research::ScientificAttestation claim{subnet.id, "job-0002", std::string(64, 'c'),
        from.address, "primegrid", 1'700'000'000'001ULL, "validator-0", {}};
    claim.proof = pqvpn::research::sign(pqvpn::research::attestation_payload(claim),
                                       validators[0].ed.private_key, validators[0].pq.secret_key);
    pqvpn::research::Block block{subnet.id, 1, subnet.epoch, std::string(64, '0'), {claim}, "validator-0"};
    pqvpn::research::FinalizedBlock finalized{block, {{"validator-0",
        pqvpn::research::sign(pqvpn::research::block_payload(block),
                              validators[0].ed.private_key, validators[0].pq.secret_key)}}};
    REQUIRE(ledger.finalize(finalized));
    pqvpn::research::Transfer transfer{subnet.id, from.address, to.address, 1, 1, {}};
    transfer.proof = pqvpn::research::sign(pqvpn::research::transfer_payload(transfer),
                                          sender.ed.private_key, sender.pq.secret_key);
    REQUIRE(ledger.transfer(transfer));
    CHECK(ledger.balance(from.address) == 0);
    CHECK(ledger.balance(to.address) == 1);
    CHECK(ledger.supply() == 1);
    CHECK(ledger.verify_invariants());
    CHECK_FALSE(ledger.transfer(transfer));
}

TEST_CASE("vote guard rejects equivocation at one height", "[research][fork]") {
    pqvpn::research::VoteGuard guard;
    CHECK(guard.record("mainnet/research", 8, "validator-a", std::string(64, 'a')));
    CHECK(guard.record("mainnet/research", 8, "validator-a", std::string(64, 'a')));
    CHECK_FALSE(guard.record("mainnet/research", 8, "validator-a", std::string(64, 'b')));
}

TEST_CASE("subnet rules reject unapproved science and disabled transfers", "[research][policy]") {
    const std::vector<Keys> validators(1);
    auto subnet = policy("mainnet/research", "mainnet", validators);
    subnet.transfers_enabled = false;
    pqvpn::research::ScientificAttestation claim{subnet.id, "job-0003", std::string(64, 'd'),
        std::string(64, 'e'), "unapproved-project", 1'700'000'000'002ULL, "validator-0", {}};
    claim.proof = pqvpn::research::sign(pqvpn::research::attestation_payload(claim),
                                       validators[0].ed.private_key, validators[0].pq.secret_key);
    CHECK_FALSE(pqvpn::research::verify_attestation(claim, subnet));
}

TEST_CASE("research checkpoints recover atomically and evidence pruning is bounded", "[research][storage]") {
    const std::vector<Keys> validators(1);
    const auto subnet = policy("mainnet/research", "mainnet", validators);
    pqvpn::research::Ledger ledger(subnet);
    const auto unique = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto root = std::filesystem::temp_directory_path() / ("pqvpn-research-" + unique);
    const auto checkpoint = root / "ledger.json";
    REQUIRE(pqvpn::research::save_checkpoint_atomic(ledger, checkpoint));
    const auto recovered = pqvpn::research::recover_checkpoint(subnet, checkpoint);
    REQUIRE(recovered);
    CHECK(recovered->height() == 0);
    CHECK(recovered->verify_invariants());

    {
        std::ofstream corrupt(checkpoint, std::ios::binary | std::ios::trunc);
        corrupt << "{not-json";
    }
    CHECK_FALSE(pqvpn::research::recover_checkpoint(subnet, checkpoint));

    const auto evidence = root / "evidence";
    std::filesystem::create_directories(evidence);
    for (int index = 0; index < 4; ++index) {
        const auto path = evidence / (std::to_string(index) + ".json");
        std::ofstream(path) << "{}\n";
        std::filesystem::last_write_time(path,
            std::filesystem::file_time_type::clock::now() + std::chrono::seconds(index));
    }
    pqvpn::research::prune_evidence(evidence, 2);
    std::size_t remaining = 0;
    for (const auto& item : std::filesystem::directory_iterator(evidence))
        if (item.path().extension() == ".json") ++remaining;
    CHECK(remaining == 2);
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}
