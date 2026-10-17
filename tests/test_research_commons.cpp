#include <catch2/catch_test_macros.hpp>
#include "research_commons.hpp"

TEST_CASE("Commons rewards useful independently confirmed work, not engagement", "[commons][reward]") {
    const auto ed = pqvpn::crypto::ed25519_keygen();
    const auto pq = pqvpn::pq_sig_keygen();
    const auto owner_ed = pqvpn::crypto::ed25519_keygen();
    const auto owner_pq = pqvpn::pq_sig_keygen();
    const pqvpn::research::PublicIdentity owner{owner_ed.public_key, owner_pq.public_key};
    const auto beneficiary = pqvpn::research::wallet_address(owner);
    pqvpn::research::SubnetPolicy policy{"mainnet/research", "mainnet", "operator",
        std::string(64, 'a'), {}, {{"validator-0", {ed.public_key, pq.public_key}}}};
    policy.allowed_projects = {"boinc-einstein", "strangenet-community"};
    pqvpn::commons::Contribution contribution{pqvpn::commons::ContributionKind::CommunityValidation,
        beneficiary, std::string(64, 'c'), "strangenet-community",
        1700000000000ULL, {std::string(64, 'd'), std::string(64, 'e')}, "validator-0", {}};
    contribution.proof = pqvpn::research::sign(pqvpn::commons::payload(contribution),
        ed.private_key, pq.secret_key);
    REQUIRE(pqvpn::commons::reward_eligible(contribution, policy));
    const auto attestation = pqvpn::commons::to_attestation(
        contribution, policy, ed.private_key, pq.secret_key);
    REQUIRE(attestation);
    CHECK(pqvpn::research::verify_attestation(*attestation, policy));

    pqvpn::research::Ledger ledger(policy);
    REQUIRE(ledger.register_wallet({owner, beneficiary}));
    pqvpn::research::Block block{policy.id, 1, policy.epoch, std::string(64, '0'),
        {*attestation}, "validator-0"};
    pqvpn::research::FinalizedBlock finalized{block, {{"validator-0",
        pqvpn::research::sign(pqvpn::research::block_payload(block),
            ed.private_key, pq.secret_key)}}};
    REQUIRE(ledger.finalize(finalized));
    CHECK(ledger.balance(beneficiary) == 1);

    SECTION("a self-signed or singly observed action cannot earn PQC") {
        contribution.confirmation_digests = {std::string(64, 'd'), std::string(64, 'd')};
        contribution.proof = pqvpn::research::sign(pqvpn::commons::payload(contribution),
            ed.private_key, pq.secret_key);
        CHECK_FALSE(pqvpn::commons::reward_eligible(contribution, policy));
    }
    SECTION("message text and attention metrics are absent from the signed payload") {
        const auto bytes = pqvpn::commons::payload(contribution);
        const std::string encoded(bytes.begin(), bytes.end());
        CHECK(encoded.find("message") == std::string::npos);
        CHECK(encoded.find("like") == std::string::npos);
        CHECK(encoded.find("duration") == std::string::npos);
    }
}
