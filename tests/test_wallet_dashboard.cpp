#include <catch2/catch_test_macros.hpp>
#include <cmath>
#include "wallet_dashboard.hpp"

TEST_CASE("wallet dashboard shows ownership PNL trend and bounded staking outlook", "[wallet][gui]") {
    const auto value = pqvpn::wallet::metrics({100'000, 21'000'000, 0.25L, 0.10L, 0.02L});
    CHECK(std::abs(value.ownership_percent - 0.476190476L) < 0.000000001L);
    REQUIRE(value.pnl);
    CHECK(std::abs(*value.pnl - 15'000.0L) < 0.000000001L);
    CHECK(value.trend == pqvpn::wallet::PnlTrend::Up);
    REQUIRE(value.projected_staking_year);
    CHECK(std::abs(*value.projected_staking_year - 2'000.0L) < 0.000000001L);
}

TEST_CASE("wallet dashboard refuses to invent market or staking values", "[wallet][gui]") {
    const auto value = pqvpn::wallet::metrics({5, 21'000'000, std::nullopt, std::nullopt, std::nullopt});
    CHECK_FALSE(value.pnl);
    CHECK(value.trend == pqvpn::wallet::PnlTrend::Unavailable);
    CHECK_FALSE(value.projected_staking_year);
}

TEST_CASE("exchange quotes are short lived and explicitly scoped", "[wallet][exchange]") {
    pqvpn::wallet::ExchangeQuote quote{"regulated-venue", "PQC/EUR", "buy", 10, 0.1L, 20'000};
    CHECK(pqvpn::wallet::valid_quote(quote, 10'000));
    quote.pair = "PQC/BTC";
    CHECK_FALSE(pqvpn::wallet::valid_quote(quote, 10'000));
    quote.pair = "PQC/EUR";
    quote.expires_at_ms = 80'001;
    CHECK_FALSE(pqvpn::wallet::valid_quote(quote, 10'000));
}
