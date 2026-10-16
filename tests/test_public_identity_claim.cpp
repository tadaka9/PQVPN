#include <catch2/catch_test_macros.hpp>

#include "crypto_utils.hpp"
#include "public_identity_claim.hpp"

TEST_CASE("public identity claims require a trusted hybrid signer", "[strangenet][identity]") {
    const auto ed = pqvpn::crypto::ed25519_keygen();
    const auto pq = pqvpn::pq_sig_keygen();
    pqvpn::identity_claim::Claim claim{
        std::string(64, 'a'), "Example Public Figure",
        pqvpn::identity_claim::Category::PublicFigure, "independent-verifier",
        "https://verifier.example/claims/1", 1000, 5000};
    const auto payload = pqvpn::identity_claim::canonical_payload(claim);
    claim.ed25519_signature = pqvpn::crypto::ed25519_sign(ed.private_key, payload);
    claim.ml_dsa_signature = pqvpn::pq_sig_sign(pq.secret_key, payload);
    const std::unordered_map<std::string, pqvpn::identity_claim::TrustedIssuer> trusted{{
        claim.issuer, {ed.public_key, pq.public_key}}};

    CHECK(pqvpn::identity_claim::verify(claim, trusted, 2000));
    CHECK_FALSE(pqvpn::identity_claim::verify(claim, {}, 2000));
    CHECK_FALSE(pqvpn::identity_claim::verify(claim, trusted, 5000));
    claim.display_name = "Impostor";
    CHECK_FALSE(pqvpn::identity_claim::verify(claim, trusted, 2000));
}
