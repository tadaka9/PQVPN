#include <catch2/catch_test_macros.hpp>
#include "console/event_state.hpp"
#include "console/terminal_text.hpp"
using namespace pqvpn::console;

TEST_CASE("Console tracks authenticated peers across connect and loss events", "[console]") {
    EventState state;const std::string peer(64,'a');
    state.accept_line("Node runtime started");CHECK_FALSE(state.authenticated());
    state.accept_line("PQVPN_EVENT {\"event\":\"peer.connected\",\"peer\":\"bad\"}");CHECK_FALSE(state.authenticated());
    state.accept_line("PQVPN_EVENT {\"event\":\"peer.connected\",\"peer\":\""+peer+"\"}");CHECK(state.authenticated());
    state.accept_line("PQVPN_EVENT {\"event\":\"peer.disconnected\",\"peer\":\""+peer+"\"}");CHECK_FALSE(state.authenticated());
}
TEST_CASE("Unverified routes and malformed events cannot establish protection", "[console]") {
    EventState state;
    state.accept_line("PQVPN_EVENT {\"event\":\"tunnel.ready\",\"fail_closed\":\"true\",\"ipv4\":\"full\"}");CHECK_FALSE(state.tunnel_ready());
    state.accept_line("PQVPN_EVENT {\"event\":\"tunnel.ready\",\"fail_closed\":true,\"ipv4\":\"full\"}");CHECK(state.tunnel_ready());
    state.accept_line("PQVPN_EVENT {\"event\":42}");CHECK(state.tunnel_ready());
    state.reset();CHECK_FALSE(state.tunnel_ready());CHECK_FALSE(state.authenticated());
}
TEST_CASE("Terminal paths and logs cannot inject controls or split UTF8 clipping", "[console]") {
    CHECK(terminal_safe("hello\033[2J\nworld")=="hello[2J world");
    CHECK(clip_ansi("\033[32mconnected\033[0m",4)=="\033[32mconn");
    CHECK(clip_ansi("café",4)=="café");
    CHECK(clip_ansi("界x",2)=="界");
}

#include "console/default_profile.hpp"
#include <random>
TEST_CASE("Installed console creates a writable profile and preserves user edits", "[console][packaging]") {
    const auto directory=std::filesystem::temp_directory_path()/("pqvpn-console-profile-test-"+std::to_string(std::random_device{}())+std::to_string(std::random_device{}()));
    std::filesystem::remove_all(directory);std::filesystem::create_directories(directory);
    const auto example=directory/"example.json";{std::ofstream output(example);output<<R"({"security":{"strict_sig_verify":true},"network":{"port":9090}})";}
    const auto profile=materialize_profile(example,directory/"user");
    REQUIRE(profile!=example);REQUIRE(std::filesystem::is_regular_file(profile));
    {std::ofstream output(profile);output<<R"({"user_edit":true})";}
    CHECK(materialize_profile(example,directory/"user")==profile);
    std::ifstream input(profile);const auto restored=nlohmann::json::parse(input);CHECK(restored.at("user_edit")==true);
    std::filesystem::remove_all(directory);
}
