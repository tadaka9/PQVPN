#include <catch2/catch_test_macros.hpp>
#include "json_utils.hpp"
#include <nlohmann/json.hpp>
#include <vector>
#include <string>

TEST_CASE("canonical_sign_bytes parity with Python", "[utils][json]") {
    using json = nlohmann::json;
    using pqvpn::utils::canonical_sign_bytes;

    SECTION("Default sorted keys (no field order)") {
        // Python: json.dumps({"b": 2, "args": 1}, separators=(",", ":"), sort_keys=True) -> b'{"a":1,"b":2}'
        json j = {{"b", 2}, {"a", 1}};
        auto result = canonical_sign_bytes(j);
        std::string res_str(result.begin(), result.end());
        CHECK(res_str == "{\"a\":1,\"b\":2}");

        // Python: json.dumps({"z": 9, "a": 0}, separators=(",", ":"), sort_keys=True) -> b'{"a":0,"z":9}'
        json j2 = {{"z", 9}, {"a", 0}};
        auto result2 = canonical_sign_bytes(j2);
        std::string res_str2(result2.begin(), result2.end());
        CHECK(res_str2 == "{\"a\":0,\"z\":9}");
    }

    SECTION("Explicit field order") {
        // Python: json.dumps({"a": 1, "b": 2}, separators=(",", ":"), sort_keys=False) with order ["b", "a"] -> b'{"b":2,"a":1}'
        json j = {{"a", 1}, {"b", 2}};
        std::vector<std::string> order = {"b", "a"};
        auto result = canonical_sign_bytes(j, order);
        std::string res_str(result.begin(), result.end());
        CHECK(res_str == "{\"b\":2,\"a\":1}");

        // Python: json.dumps({"a": 1, "b": 2}, separators=(",", ":"), sort_keys=False) with order ["a"] -> b'{"a":1}'
        std::vector<std::string> subset = {"a"};
        auto result2 = canonical_sign_bytes(j, subset);
        std::string res_str2(result2.begin(), result2.end());
        CHECK(res_str2 == "{\"a\":1}");
    }

    SECTION("Handle missing fields in order") {
        // Python: if field is in order but not in obj, it is skipped
        json j = {{"a", 1}};
        std::vector<std::string> order = {"b", "to_be_added", "a"};
        auto result = canonical_sign_bytes(j, order);
        std::string res_str(result.begin(), result.end());
        CHECK(res_str == "{\"a\":1}");
    }

    SECTION("Deeply nested objects") {
        // Python: json.dumps({"a": {"z": 9, "b": 0}}, separators=(",", ":"), sort_keys=True) -> b'{"a":{"b":0,"z":9}}'
        json j = {{"a", {{"z", 9}, {"b", 0}}}};
        auto result = canonical_sign_bytes(j);
        std::string res_str(result.begin(), result.end());
        CHECK(res_str == "{\"a\":{\"b\":0,\"z\":9}}");
    }
}
