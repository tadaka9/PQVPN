#include <catch2/catch_test_macros.hpp>
#include "resource_market.hpp"
#include "node_module.hpp"
TEST_CASE("signed resource offers select useful low latency capacity","[resource]"){
 auto ed=pqvpn::crypto::ed25519_keygen();auto pq=pqvpn::pq_sig_keygen();pqvpn::research::PublicIdentity id{ed.public_key,pq.public_key};auto address=pqvpn::research::wallet_address(id);
 pqvpn::resource::Offer fast{pqvpn::resource::Kind::RelayAcceleration,address,std::string(64,'a'),20,1'000'000'000,990'000,2000,{}};fast.proof=pqvpn::research::sign(pqvpn::resource::payload(fast),ed.private_key,pq.secret_key);
 auto slow=fast;slow.peer_id=std::string(64,'b');slow.latency_ms=200;slow.proof=pqvpn::research::sign(pqvpn::resource::payload(slow),ed.private_key,pq.secret_key);
 auto selected=pqvpn::resource::choose({slow,fast},pqvpn::resource::Kind::RelayAcceleration,1000,{{address,id}});REQUIRE(selected);CHECK(selected->peer_id==fast.peer_id);
 fast.capacity_bps=0;CHECK_FALSE(pqvpn::resource::valid(fast,id,1000));
}
TEST_CASE("node accepts only a verified relay acceleration offer","[resource][dataplane]"){
 asio::io_context io;pqvpn::PQVPNNode node(io,"config.json");auto ed=pqvpn::crypto::ed25519_keygen();auto pq=pqvpn::pq_sig_keygen();pqvpn::research::PublicIdentity id{ed.public_key,pq.public_key};
 pqvpn::resource::Offer offer{pqvpn::resource::Kind::RelayAcceleration,pqvpn::research::wallet_address(id),std::string(64,'c'),25,500'000'000,980'000,2000,{}};offer.proof=pqvpn::research::sign(pqvpn::resource::payload(offer),ed.private_key,pq.secret_key);
 CHECK(node.accept_acceleration_offer(offer,id,1000));offer.kind=pqvpn::resource::Kind::StorageRetrieval;CHECK_FALSE(node.accept_acceleration_offer(offer,id,1000));
}
TEST_CASE("service receipt proves bounded work without navigation metadata","[resource][receipt]"){
 auto ed=pqvpn::crypto::ed25519_keygen();auto pq=pqvpn::pq_sig_keygen();pqvpn::research::PublicIdentity id{ed.public_key,pq.public_key};pqvpn::resource::ServiceReceipt receipt{std::string(64,'d'),pqvpn::research::wallet_address(id),1<<20,1000,1700000000000ULL,1,{}};receipt.proof=pqvpn::research::sign(pqvpn::resource::receipt_payload(receipt),ed.private_key,pq.secret_key);CHECK(pqvpn::resource::valid_receipt(receipt,id));const auto payload=pqvpn::resource::receipt_payload(receipt);CHECK(std::string(payload.begin(),payload.end()).find("url")==std::string::npos);
}
