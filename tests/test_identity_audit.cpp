#include <catch2/catch_test_macros.hpp>
#include "node_module.hpp"
#include "node_identity.hpp"
#include <random>

TEST_CASE("Base32 matches RFC 4648 vectors", "[crypto]") {
    const std::vector<std::pair<std::string, std::string>> vectors{
        {"", ""}, {"f", "MY======"}, {"fo", "MZXQ===="}, {"foo", "MZXW6==="},
        {"foob", "MZXW6YQ="}, {"fooba", "MZXW6YTB"}, {"foobar", "MZXW6YTBOI======"}};
    for (const auto& [input, expected] : vectors) {
        const auto output = pqvpn::crypto::base32_encode({input.begin(), input.end()});
        CHECK(std::string(output.begin(), output.end()) == expected);
    }
}

TEST_CASE("Existing broken identities fail closed and temporary files are preserved", "[identity]") {
    const auto directory = std::filesystem::temp_directory_path() /
        ("pqvpn-identity-audit-" + std::to_string(std::random_device{}()));
    std::filesystem::create_directory(directory);
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::filesystem::remove_all(path); } } cleanup{directory};
    const auto path = directory / "node_keys.json";
    { std::ofstream output(path); output << "corrupted"; }
    asio::io_context io;
    pqvpn::PQVPNNode node(io, (directory / "config.json").string());
    CHECK_FALSE(node.load_or_create_identity());
    std::ifstream input(path);
    CHECK(std::string(std::istreambuf_iterator<char>(input), {}) == "corrupted");
    { std::ofstream output(path.string() + ".tmp"); output << "existing"; }
    CHECK_THROWS(pqvpn::identity::write_private_file(path.string(), "new"));
    std::ifstream temporary(path.string() + ".tmp");
    CHECK(std::string(std::istreambuf_iterator<char>(temporary), {}) == "existing");
    std::filesystem::remove(path.string() + ".tmp");
    CHECK_THROWS(pqvpn::identity::write_private_file(path.string(), "replacement"));
    std::filesystem::remove(path);
    pqvpn::identity::write_private_file(path.string(), "private");
#ifndef _WIN32
    CHECK((std::filesystem::status(path).permissions() &
          (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) ==
          std::filesystem::perms::none);
#endif
}

TEST_CASE("Relocated profiles keep the original identity without touching destination keys", "[identity]") {
    const auto root = std::filesystem::temp_directory_path() /
        ("pqvpn-identity-profile-" + std::to_string(std::random_device{}()));
    std::filesystem::create_directory(root);
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::filesystem::remove_all(path); } } cleanup{root};
    std::filesystem::create_directory(root / "profiles");
    const auto identity_path = root / "node_keys.json";
    const auto original = pqvpn::identity::NodeIdentity::generate();
    original.save(identity_path.string());
    const auto destination_keys = root / "profiles" / "node_keys.json";
    { std::ofstream output(destination_keys); output << "unrelated destination identity"; }
    const auto profile = root / "profiles" / "udp2raw.json";
    { std::ofstream output(profile); output << nlohmann::json{
        {"security", {{"identity_file", identity_path.string()}}}}.dump(); }
    asio::io_context io;
    pqvpn::PQVPNNode node(io, profile.string());
    REQUIRE(node.load_or_create_identity());
    CHECK(node.ed25519_public_key == original.ed25519_pk);
    CHECK(node.ml_kem_public_key == original.ml_kem_pk);
    std::ifstream untouched(destination_keys);
    CHECK(std::string(std::istreambuf_iterator<char>(untouched), {}) == "unrelated destination identity");
    // Relative explicit paths resolve against the new profile, not the process cwd.
    { std::ofstream output(profile); output << nlohmann::json{
        {"security", {{"identity_file", "../node_keys.json"}}}}.dump(); }
    pqvpn::PQVPNNode relative(io, profile.string());
    REQUIRE(relative.load_or_create_identity());
    CHECK(relative.ed25519_public_key == original.ed25519_pk);
}
