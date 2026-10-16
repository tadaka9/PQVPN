#include <catch2/catch_test_macros.hpp>

#include "group_chat.hpp"

TEST_CASE("a group requires three distinct participants and is canonical", "[strangenet][group]") {
    const std::string local(64, 'a');
    std::vector<std::string> peers{std::string(64, 'C'), std::string(64, 'b')};
    REQUIRE(pqvpn::group_chat::canonicalize_members(local, peers));
    CHECK(peers == std::vector<std::string>{std::string(64, 'b'), std::string(64, 'c')});

    std::vector<std::string> only_one{std::string(64, 'b')};
    CHECK_FALSE(pqvpn::group_chat::canonicalize_members(local, only_one));
    std::vector<std::string> duplicate{std::string(64, 'b'), std::string(64, 'b')};
    CHECK_FALSE(pqvpn::group_chat::canonicalize_members(local, duplicate));
    std::vector<std::string> includes_local{local, std::string(64, 'b')};
    CHECK_FALSE(pqvpn::group_chat::canonicalize_members(local, includes_local));
}
