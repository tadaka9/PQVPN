#include <catch2/catch_test_macros.hpp>
#include "resource_market.hpp"
TEST_CASE("signed resource offers select useful low latency capacity","[resource]"){
 auto ed=pqvpn::crypto::ed25519_keygen();auto pq=pqvpn::pq_sig_keygen();pqvpn::research::PublicIdentity id{ed.public_key,pq.public_key};auto address=pqvpn::research::wallet_address(id);
 pqvpn::resource::Offer fast{pqvpn::resource::Kind::RelayAcceleration,address,std::string(64,'a'),20,1'000'000'000,990'000,2000,{}};fast.proof=pqvpn::research::sign(pqvpn::resource::payload(fast),ed.private_key,pq.secret_key);
 auto slow=fast;slow.peer_id=std::string(64,'b');slow.latency_ms=200;slow.proof=pqvpn::research::sign(pqvpn::resource::payload(slow),ed.private_key,pq.secret_key);
 auto selected=pqvpn::resource::choose({slow,fast},pqvpn::resource::Kind::RelayAcceleration,1000,{{address,id}});REQUIRE(selected);CHECK(selected->peer_id==fast.peer_id);
 fast.capacity_bps=0;CHECK_FALSE(pqvpn::resource::valid(fast,id,1000));
}
