#ifndef PQVPN_STRING_UTILS_HPP
#define PQVPN_STRING_UTILS_HPP

#include <string>
#include <algorithm>
#include <cctype>

namespace pqvpn {

std::string lowercase(const std::string& input);

} // namespace pqvpn

namespace pqvpn::utils {

inline std::string normalize_sig_config_name(const std::string& algorithm) {
    if (algorithm.empty()) return "mldsa87";
    std::string result;
    result.reserve(algorithm.size());
    for (const unsigned char ch : algorithm) {
        if (std::isalnum(ch)) result.push_back(static_cast<char>(std::tolower(ch)));
    }
    return result;
}

} // namespace pqvpn::utils

#endif // PQVPN_STRING_UTILS_HPP
