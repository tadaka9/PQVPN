#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <oqs/oqs.h>

namespace fs = std::filesystem;
using nlohmann::json;

namespace {
std::string read(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot read " + path.string());
    return {std::istreambuf_iterator<char>(file), {}};
}

// Arguments come from CMake, but quote them even when the checkout contains
// spaces or shell metacharacters. Reject expansion syntax on cmd.exe.
std::string quote(const std::string& value) {
#ifdef _WIN32
    if (value.find_first_of("\"%\r\n") != std::string::npos)
        throw std::runtime_error("Unsafe Windows command argument");
    return "\"" + value + "\"";
#else
    std::string result = "'";
    for (char c : value) result += c == '\'' ? "'\\''" : std::string(1, c);
    return result + "'";
#endif
}

int run(const fs::path& root, const fs::path& build,
        const fs::path& ctest, const std::string& config) {
    json findings = json::array();
    auto add = [&](std::string gate, const fs::path& path,
                   std::size_t line, std::string message) {
        findings.push_back({{"severity", "error"}, {"gate", gate},
            {"path", path.lexically_relative(root).generic_string()},
            {"line", line}, {"message", message}});
    };
    const auto flags = std::regex::ECMAScript | std::regex::icase;
    // Preserve the original gate's marker policy. co_return true is an
    // actual coroutine result, so the word boundary excludes that spelling.
    const std::regex forbidden(
        R"(\b(stub|placeholder|fake|dummy|simulate|simulation|simulated|for now|not implemented|no-op|hollow|fallback to random|return true\s*;?\s*(?://.*placeholder)?)\b)", flags);
    const std::regex hollow(
        R"(REQUIRE\s*\(\s*true\s*\)|EXPECT_TRUE\s*\(\s*true\s*\)|SUCCEED\s*\()");
    const std::regex weak(
        R"(\b(Kyber512|Kyber768|ML-KEM-512|ML-KEM-768|Dilithium2|Dilithium3|Dilithium5|ML-DSA-44|ML-DSA-65)\b)");
    std::string all_source;
    std::size_t files = 0;
    for (const auto& dir : {root / "src", root / "tests"}) {
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            const auto ext = entry.path().extension().string();
            if (ext != ".cpp" && ext != ".hpp" && ext != ".h" &&
                ext != ".ixx" && ext != ".c" && ext != ".cc") continue;
            const auto text = read(entry.path());
            all_source += text + '\n';
            ++files;
            std::ifstream stream(entry.path());
            std::string line;
            std::size_t number = 0;
            while (std::getline(stream, line)) {
                ++number;
                if (std::regex_search(line, forbidden) || std::regex_search(line, hollow))
                    add("no_fake_progress", entry.path(), number, line.substr(0, 180));
                if (std::regex_search(line, weak))
                    add("mandatory_algorithms_only", entry.path(), number, line.substr(0, 180));
            }
        }
    }
    const std::map<std::string, std::string> required = {
        {"ML-KEM-1024", R"(\b(Kyber1024|ML-KEM-1024|ML_KEM_1024|ml_kem_1024)\b)"},
        {"X25519", R"(\bX25519\b)"},
        {"Ed25519", R"(\b(Ed25519|ed25519)\b)"},
        {"ML-DSA-87", R"(\b(ML-DSA-87|ML_DSA_87|ml_dsa_87)\b)"}
    };
    for (const auto& [name, pattern] : required)
        if (!std::regex_search(all_source, std::regex(pattern)))
            add("mandatory_algorithms_present", root / "CMakeLists.txt", 1, name);

    // Link and exercise the configured provider instead of inferring it from
    // pkg-config files or installed headers. Disabled algorithms fail closed.
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_ml_kem_1024) ||
        !OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_87))
        add("liboqs_algorithms", root / "CMakeLists.txt", 1,
            "The linked liboqs must enable ML-KEM-1024 and ML-DSA-87");
    std::string crypto;
    for (const auto& file : {"src/crypto_utils.cpp", "src/crypto_signature.cpp",
                            "src/modules/crypto_module.hpp", "src/modules/crypto_kem.cpp"})
        crypto += read(root / file);
    for (const auto& token : {"OQS_KEM", "OQS_SIG", "X25519"})
        if (crypto.find(token) == std::string::npos)
            add("real_crypto", root / "src/modules/crypto_module.hpp", 1, token);

    const auto main = read(root / "src/main.cpp");
    for (const auto& token : {"--smoke-test", "io.run()", "session_maintenance"})
        if (main.find(token) == std::string::npos)
            add("runtime_liveness", root / "src/main.cpp", 1, token);
    const auto network = read(root / "src/modules/network_module.hpp") +
        read(root / "src/modules/udp_protocol.cpp") + read(root / "src/modules/node_module.hpp");
    for (const auto& token : {"async_receive_from", "datagram_received", "co_spawn"})
        if (network.find(token) == std::string::npos)
            add("udp_receive_dispatch", root / "src/modules/network_module.hpp", 1, token);

    if (!fs::is_regular_file(build / "CTestTestfile.cmake")) {
        add("build_state", build, 1, "Missing CTest configuration");
    } else {
        std::string command = quote(ctest.string()) + " --test-dir " + quote(build.string()) +
            " -LE hardening --parallel 2 --output-on-failure";
        if (!config.empty()) command += " --build-config " + quote(config);
#ifdef _WIN32
        command = "\"" + command + "\"";
#endif
        if (std::system(command.c_str()) != 0)
            add("ctest", build, 1, "CTest failed");
    }
    const bool ok = findings.empty();
    const json payload = {{"ok", ok}, {"summary", {
        {"errors", findings.size()}, {"warnings", 0}, {"files_scanned", files},
        {"liboqs_linked", true}}}, {"findings", findings}};
    fs::create_directories(root / ".loop-engineering");
    std::ofstream report(root / ".loop-engineering/hard_kernel_report.json");
    report << payload.dump(2) << '\n';
    if (!report) throw std::runtime_error("Cannot write hardening report");
    std::cout << payload.dump(2) << '\n';
    return ok ? 0 : 2;
}
} // namespace

int main(int argc, char** argv) {
    try {
        std::map<std::string, std::string> args;
        for (int i = 1; i < argc; i += 2) {
            if (i + 1 == argc) throw std::runtime_error("Missing argument value");
            args[argv[i]] = argv[i + 1];
        }
        for (const auto& name : {"--source", "--build", "--ctest"})
            if (!args.contains(name)) throw std::runtime_error(std::string("Missing ") + name);
        return run(fs::absolute(args.at("--source")), fs::absolute(args.at("--build")),
                   args.at("--ctest"), args["--config"]);
    } catch (const std::exception& error) {
        std::cerr << "Hardening gate failed: " << error.what() << '\n';
        return 2;
    }
}
