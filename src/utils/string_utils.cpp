#include "string_utils.hpp"
#include <algorithm>
#include <cctype>

namespace pqvpn {

std::string lowercase(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return result;
}

} // namespace pqvpn