#pragma once

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "node_identity.hpp"
#include "private_file.hpp"
#include "research_ledger.hpp"
#include "creator_registry.hpp"

namespace pqvpn::wallet {

struct SelfCustodyIdentity {
    crypto::Ed25519KeyPair ed25519;
    SigKeyPair ml_dsa_87;

    static SelfCustodyIdentity generate() {
        return {crypto::ed25519_keygen(), pq_sig_keygen()};
    }

    research::PublicIdentity public_identity() const {
        return {ed25519.public_key, ml_dsa_87.public_key};
    }

    std::string address() const { return research::wallet_address(public_identity()); }

    void save(const std::filesystem::path& path) const {
        const nlohmann::ordered_json value{{"domain", "PQVPN/self-custody-wallet/v1"},
            {"ed25519_pk", identity::to_hex(ed25519.public_key)},
            {"ed25519_sk", identity::to_hex(ed25519.private_key)},
            {"ml_dsa_87_pk", identity::to_hex(ml_dsa_87.public_key)},
            {"ml_dsa_87_sk", identity::to_hex(ml_dsa_87.secret_key)}, {"version", 1}};
        identity::write_private_file(path.string(), value.dump(2) + "\n");
    }

    static SelfCustodyIdentity load(const std::filesystem::path& path) {
        std::ifstream input(path, std::ios::binary);
        if (!input) throw std::runtime_error("cannot open wallet identity");
        const auto value = nlohmann::json::parse(input);
        if (value.value("domain", std::string{}) != "PQVPN/self-custody-wallet/v1" ||
            value.value("version", 0) != 1) throw std::runtime_error("unsupported wallet identity");
        auto field = [&](const char* name) {
            auto decoded = identity::from_hex(value.value(name, std::string{}));
            if (!decoded || decoded->empty()) throw std::runtime_error(std::string("wallet missing ") + name);
            return *decoded;
        };
        SelfCustodyIdentity result{{field("ed25519_pk"), field("ed25519_sk")},
                                   {field("ml_dsa_87_pk"), field("ml_dsa_87_sk")}};
        const research::Bytes challenge{'P','Q','V','P','N','/','w','a','l','l','e','t','/','c','h','e','c','k'};
        const auto proof = research::sign(challenge, result.ed25519.private_key,
                                          result.ml_dsa_87.secret_key);
        if (!research::verify(challenge, result.public_identity(), proof))
            throw std::runtime_error("wallet public/private key mismatch");
        return result;
    }
};

inline SelfCustodyIdentity load_or_create(const std::filesystem::path& path) {
    std::error_code error;
    if (std::filesystem::exists(path, error)) return SelfCustodyIdentity::load(path);
    if (error) throw std::runtime_error("cannot inspect wallet path");
    auto identity = SelfCustodyIdentity::generate();
    identity.save(path);
    return identity;
}

inline std::filesystem::path path_for_config(const std::filesystem::path& config) {
    const auto parent=config.has_parent_path()?config.parent_path():std::filesystem::current_path();
    return parent/"wallet_keys.json";
}

inline nlohmann::ordered_json public_status(const SelfCustodyIdentity& identity) {
    const bool creator=is_creator_wallet(identity.address());
    return {{"address", identity.address()}, {"custody", "local-self-custody"},
            {"key_domains", nlohmann::ordered_json::array({"Ed25519", "ML-DSA-87"})},
            {"private_keys_exported", false}, {"creator_verified", creator},
            {"creator_name", creator ? std::string(creator_name) : std::string{}},
            {"economic_mainnet", "not-deployed"}, {"balance_finalized", false},
            {"max_supply", 21'000'000}, {"version", 1}};
}

} // namespace pqvpn::wallet
