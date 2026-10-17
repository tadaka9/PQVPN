#pragma once
#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "research_ledger.hpp"

namespace pqvpn::resource {
enum class Kind { RelayAcceleration, StorageRetrieval };
struct Offer { Kind kind; std::string provider_wallet;std::string peer_id;std::uint32_t latency_ms=0;
 std::uint64_t capacity_bps=0;std::uint32_t availability_ppm=0;std::uint64_t expires_at_ms=0;research::HybridProof proof;};
inline research::Bytes payload(const Offer& o){return research::encode({{"availability_ppm",o.availability_ppm},{"capacity_bps",o.capacity_bps},{"domain","PQVPN/resource-offer/v1"},{"expires_at_ms",o.expires_at_ms},{"kind",o.kind==Kind::RelayAcceleration?"relay":"storage"},{"latency_ms",o.latency_ms},{"peer_id",o.peer_id},{"provider_wallet",o.provider_wallet}});}
inline bool valid(const Offer& o,const research::PublicIdentity& id,std::uint64_t now){return research::wallet_address(id)==o.provider_wallet&&group_chat::valid_peer_id(o.peer_id)&&o.capacity_bps>0&&o.latency_ms>0&&o.availability_ppm<=1'000'000&&o.availability_ppm>=900'000&&o.expires_at_ms>now&&o.expires_at_ms-now<=3'600'000&&research::verify(payload(o),id,o.proof);}
inline std::optional<Offer> choose(const std::vector<Offer>& offers,Kind kind,std::uint64_t now,const std::map<std::string,research::PublicIdentity>& identities){
 std::vector<Offer> eligible;for(const auto&o:offers){auto it=identities.find(o.provider_wallet);if(o.kind==kind&&it!=identities.end()&&valid(o,it->second,now))eligible.push_back(o);}if(eligible.empty())return std::nullopt;
 std::sort(eligible.begin(),eligible.end(),[](const Offer&a,const Offer&b){const long double as=static_cast<long double>(a.capacity_bps)*a.availability_ppm/(a.latency_ms+1),bs=static_cast<long double>(b.capacity_bps)*b.availability_ppm/(b.latency_ms+1);return as!=bs?as>bs:a.peer_id<b.peer_id;});return eligible.front();}
struct ServiceReceipt { std::string offer_digest;std::string provider_wallet;std::uint64_t byte_bucket=0;
 std::uint64_t duration_bucket_ms=0;std::uint64_t completed_at_ms=0;std::uint64_t nonce=0;research::HybridProof proof;};
inline research::Bytes receipt_payload(const ServiceReceipt&r){return research::encode({{"byte_bucket",r.byte_bucket},{"completed_at_ms",r.completed_at_ms},{"domain","PQVPN/resource-receipt/v1"},{"duration_bucket_ms",r.duration_bucket_ms},{"nonce",r.nonce},{"offer_digest",r.offer_digest},{"provider_wallet",r.provider_wallet}});}
inline bool valid_receipt(const ServiceReceipt&r,const research::PublicIdentity&id){return group_chat::valid_peer_id(r.offer_digest)&&research::wallet_address(id)==r.provider_wallet&&r.byte_bucket>0&&r.duration_bucket_ms>0&&r.completed_at_ms>0&&r.nonce>0&&research::verify(receipt_payload(r),id,r.proof);}
}
