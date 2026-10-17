#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <fstream>
#include <random>
#include "wallet_identity.hpp"

TEST_CASE("each installation keeps a distinct fail-closed self-custody wallet", "[wallet]") {
    const auto root=std::filesystem::temp_directory_path()/("pqvpn-wallet-"+std::to_string(std::random_device{}()));
    std::filesystem::create_directories(root);
    struct Cleanup{std::filesystem::path p;~Cleanup(){std::filesystem::remove_all(p);}} cleanup{root};
    const auto first_path=root/"first.json", second_path=root/"second.json";
    const auto first=pqvpn::wallet::load_or_create(first_path);
    const auto stable=pqvpn::wallet::load_or_create(first_path);
    const auto second=pqvpn::wallet::load_or_create(second_path);
    CHECK(first.address()==stable.address());
    CHECK(first.address()!=second.address());
    CHECK(pqvpn::wallet::public_status(first).at("private_keys_exported")==false);
    CHECK(pqvpn::wallet::public_status(first).at("balance_finalized")==false);
    CHECK(pqvpn::wallet::public_status(first).at("max_supply")==21'000'000);
    CHECK(pqvpn::wallet::is_creator_wallet(pqvpn::wallet::creator_wallet));
#ifndef _WIN32
    CHECK((std::filesystem::status(first_path).permissions() &
          (std::filesystem::perms::group_all|std::filesystem::perms::others_all))==std::filesystem::perms::none);
#endif
    {std::ofstream corrupt(first_path,std::ios::trunc);corrupt<<"{}";}
    CHECK_THROWS(pqvpn::wallet::load_or_create(first_path));
}
