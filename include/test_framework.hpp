#ifndef PQVPN_TEST_FRAMEWORK_HPP
#define PQVPN_TEST_FRAMEWORK_HPP

#include <iostream>
#include <string>
#include <vector>
#include <functional>

namespace pqvpn::test {

struct TestCase {
    std::string name;
    std::function<void()> func;
};

class TestRunner {
public:
    static void add_test(const std::string& name, std::function<void()> func) {
        get_tests().push_back({name, func});
    }

    static int run_all() {
        int failed = 0;
        auto& tests = get_tests();
        std::cout << "Running " << tests.size() << " tests...\n";

        for (const auto& test : tests) {
            try {
                test.func();
                std::cout << "[ PASS ] " << test.name << "\n";
            } catch (const std::exception& e) {
                std::cerr << "[ FAIL ] " << test.name << " - Exception: " << e.what() << "\n";
                failed++;
            } catch (...) {
                std::cerr << "[ FAIL ] " << test.name << " - Unknown error\n";
                failed++;
            }
        }

        if (failed == 0) {
            std::cout << "All tests passed!\n";
        } else {
            std::cout << failed << " test(s) failed.\n";
        }
        return failed;
    }

private:
    static std::vector<TestCase>& get_tests() {
        static std::vector<TestCase> tests;
        return tests;
    }
};

#define TEST_CASE(name) \
    void name(); \
    namespace { struct reg_##name { reg_##name() { pqvpn::test::TestRunner::add_test(#name, name); } } reg_##name; } \
    void name()

#define ASSERT_TRUE(cond) \
    if (!(cond)) throw std::runtime_error("Assertion failed: " #cond " at line " + std::to_string(__LINE__))

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

} // namespace pqvpn::test

#endif // PQVPN_TEST_FRAMEWORK_HPP
