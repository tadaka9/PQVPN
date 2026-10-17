#pragma once

#include <string_view>

namespace pqvpn::wallet {

inline constexpr std::string_view creator_name = "Davide Di Pino";
inline constexpr std::string_view creator_handle = "tadaka9";
inline constexpr std::string_view creator_wallet =
    "a27e59fceb4cca6cdb79508a43bbfaec77caa8ac99b43a7ea31f93c82ea6176c";

inline bool is_creator_wallet(std::string_view address) noexcept {
    return address == creator_wallet;
}

} // namespace pqvpn::wallet
