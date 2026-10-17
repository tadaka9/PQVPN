#include <catch2/catch_test_macros.hpp>
#include "crypto_utils.hpp"
#include "science_validator_adapter.hpp"
TEST_CASE("only project-signed valid receipts become attestations","[research][adapter]"){
 const auto project_ed=pqvpn::crypto::ed25519_keygen();const auto project_pq=pqvpn::pq_sig_keygen();
 const auto validator_ed=pqvpn::crypto::ed25519_keygen();const auto validator_pq=pqvpn::pq_sig_keygen();
 pqvpn::research::ProjectAdapter adapter({{"einstein-at-home",{project_ed.public_key,project_pq.public_key}}});
 pqvpn::research::ProjectReceipt receipt{"einstein-at-home","mainnet/research","job-4",std::string(64,'b'),std::string(64,'c'),"valid",1700000000000,{}};
 receipt.project_proof=pqvpn::research::sign(pqvpn::research::project_receipt_payload(receipt),project_ed.private_key,project_pq.secret_key);
 CHECK(adapter.ingest(receipt,"validator-0",validator_ed.private_key,validator_pq.secret_key));
 receipt.outcome="invalid";CHECK_FALSE(adapter.ingest(receipt,"validator-0",validator_ed.private_key,validator_pq.secret_key));
}
