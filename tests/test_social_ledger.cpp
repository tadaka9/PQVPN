#include <catch2/catch_test_macros.hpp>
#include "social_ledger.hpp"

TEST_CASE("StrangeNet achievement binds a wallet without leaking social content", "[social][ledger]") {
    const auto ed = pqvpn::crypto::ed25519_keygen();
    const auto pq = pqvpn::pq_sig_keygen();
    const pqvpn::research::PublicIdentity identity{ed.public_key, pq.public_key};
    pqvpn::social::Claim claim{pqvpn::research::wallet_address(identity),
        pqvpn::social::Achievement::DistrictDiscovered, std::string(64, 'a'), 1000, 1, {}};
    claim.proof = pqvpn::research::sign(pqvpn::social::payload(claim), ed.private_key, pq.secret_key);
    REQUIRE(pqvpn::social::valid(claim, identity));
    const auto encoded = pqvpn::social::payload(claim);
    const std::string text(encoded.begin(), encoded.end());
    CHECK(text.find("message") == std::string::npos);
    CHECK(text.find("room") == std::string::npos);
    CHECK(text.find("coordinate") == std::string::npos);
    claim.nonce++;
    CHECK_FALSE(pqvpn::social::valid(claim, identity));
}
