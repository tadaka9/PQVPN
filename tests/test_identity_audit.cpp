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
    pqvpn::identity::write_private_file(path.string(), "private");
#ifndef _WIN32
    CHECK((std::filesystem::status(path).permissions() &
          (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) ==
          std::filesystem::perms::none);
#endif
}
