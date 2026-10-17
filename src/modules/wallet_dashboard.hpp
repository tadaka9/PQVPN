#pragma once

#include <cmath>
#include <cstdint>
#include <optional>
#include <string>

namespace pqvpn::wallet {

enum class PnlTrend { Unavailable, Down, Flat, Up };

struct DashboardInput {
    std::uint64_t balance = 0;
    std::uint64_t max_supply = 21'000'000;
    std::optional<long double> reference_price;
    std::optional<long double> cost_basis;
    std::optional<long double> annual_staking_rate;
};

struct DashboardMetrics {
    long double ownership_percent = 0;
    std::optional<long double> pnl;
    PnlTrend trend = PnlTrend::Unavailable;
    std::optional<long double> projected_staking_year;
};

inline DashboardMetrics metrics(const DashboardInput& input) {
    DashboardMetrics result;
    if (input.max_supply != 0)
        result.ownership_percent = 100.0L * input.balance / input.max_supply;
    if (input.reference_price && input.cost_basis && *input.reference_price >= 0 &&
        *input.cost_basis >= 0) {
        result.pnl = input.balance * (*input.reference_price - *input.cost_basis);
        constexpr long double epsilon = 0.00000001L;
        result.trend = *result.pnl > epsilon ? PnlTrend::Up :
            *result.pnl < -epsilon ? PnlTrend::Down : PnlTrend::Flat;
    }
    if (input.annual_staking_rate && *input.annual_staking_rate >= 0 &&
        *input.annual_staking_rate <= 1)
        result.projected_staking_year = input.balance * *input.annual_staking_rate;
    return result;
}

struct ExchangeQuote {
    std::string venue;
    std::string pair;
    std::string side;
    long double amount = 0;
    long double unit_price = 0;
    std::uint64_t expires_at_ms = 0;
};

inline bool valid_quote(const ExchangeQuote& quote, std::uint64_t now_ms) {
    return !quote.venue.empty() && quote.venue.size() <= 128 && quote.pair == "PQC/EUR" &&
        (quote.side == "buy" || quote.side == "sell") && std::isfinite(quote.amount) &&
        std::isfinite(quote.unit_price) && quote.amount > 0 && quote.unit_price > 0 &&
        quote.expires_at_ms > now_ms && quote.expires_at_ms - now_ms <= 60'000;
}

} // namespace pqvpn::wallet
