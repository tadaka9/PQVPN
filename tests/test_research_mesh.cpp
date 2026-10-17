#include <catch2/catch_test_macros.hpp>
#include "crypto_utils.hpp"
#include "research_mesh.hpp"

TEST_CASE("research mesh envelopes are authenticated bounded and replay safe", "[research][mesh]") {
    const auto ed = pqvpn::crypto::ed25519_keygen(); const auto pq = pqvpn::pq_sig_keygen();
    pqvpn::research::SubnetPolicy policy{"mainnet/research", "mainnet", "operator",
        std::string(64, 'a'), {"science-only"}, {{"validator", {ed.public_key, pq.public_key}}}};
    pqvpn::research::mesh::Envelope message{pqvpn::research::mesh::Kind::Proposal,
        policy.id, "validator", 1, 1, {{"height", 1}}, {}};
    message.proof = pqvpn::research::sign(pqvpn::research::mesh::payload(message), ed.private_key, pq.secret_key);
    REQUIRE(pqvpn::research::mesh::verify_envelope(message, policy));
    pqvpn::research::mesh::ReplayGuard guard;
    CHECK(guard.accept(message));
    CHECK_FALSE(guard.accept(message));
    message.body["height"] = 2;
    CHECK_FALSE(pqvpn::research::mesh::verify_envelope(message, policy));
}

TEST_CASE("partition mode permits catchup but not mint proposals", "[research][partition]") {
    using pqvpn::research::mesh::Kind;
    CHECK_FALSE(pqvpn::research::mesh::accepts_during_partition(Kind::Proposal));
    CHECK_FALSE(pqvpn::research::mesh::accepts_during_partition(Kind::Certificate));
    CHECK(pqvpn::research::mesh::accepts_during_partition(Kind::CatchupRequest));
    CHECK(pqvpn::research::mesh::accepts_during_partition(Kind::CatchupResponse));
}
