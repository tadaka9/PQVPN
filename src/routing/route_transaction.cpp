#include "routing/route_transaction.hpp"

#include <algorithm>

namespace pqvpn::routing {

void RouteTransaction::add(RouteEntry entry) {
    if (!entry.valid()) {
        throw std::invalid_argument("route entry needs a prefix, a gateway, and a valid prefix length");
    }
    entries_.push_back(std::move(entry));
}

const std::vector<RouteEntry>& RouteTransaction::entries() const noexcept {
    return entries_;
}

bool RouteTransaction::empty() const noexcept {
    return entries_.empty();
}

CommitReport RouteTransaction::commit(RouteBackend& backend) {
    CommitReport report;
    std::vector<std::size_t> created; // indices installed and not already present
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        const auto result = backend.install(entries_[index]);
        if (!result.ok) {
            report.failed_index = index;
            report.error = result.error.empty() ? "route install failed" : result.error;
            // Roll back only the entries this commit created, in reverse order.
            // Already-present routes are left alone: they pre-date us and must
            // survive a failed commit. A rollback that itself fails is recorded:
            // the caller must treat the table as uncertain and inspect it manually.
            for (auto it = created.rbegin(); it != created.rend(); ++it) {
                const auto rollback = backend.remove(entries_[*it]);
                if (!rollback.ok) {
                    report.error += "; rollback of an installed entry failed";
                    break;
                }
                report.rolled_back.push_back(entries_[*it]);
            }
            owned_.clear(); // nothing survives a failed commit for us to clean up
            return report;
        }
        if (!result.already_present) {
            created.push_back(index);
        }
    }
    owned_ = std::move(created); // these are the routes we own for cleanup
    report.committed = true;
    return report;
}

RemovalReport RouteTransaction::remove_all(RouteBackend& backend) {
    RemovalReport report;
    bool failed = false;
    std::vector<std::size_t> released; // indices whose removal was confirmed
    // Remove only the routes this transaction created (owned_). Routes that
    // were already present when we committed are not ours to delete.
    for (const auto index : owned_) {
        const auto result = backend.remove(entries_[index]);
        if (!result.ok) {
            // Best-effort cleanup: record the first hard failure, keep this
            // entry owned for a later retry, and remove the rest.
            if (!failed) {
                report.error = result.error.empty() ? "route removal failed" : result.error;
                failed = true;
            }
            continue;
        }
        released.push_back(index);
        if (result.not_found) {
            ++report.already_absent;
        } else {
            ++report.removed;
        }
    }
    // Confirmed removal ends our ownership NOW: a later cleanup pass must not
    // delete a route someone else recreated after we relinquished it. Hard
    // failures stay in owned_ so they are retried.
    for (const auto index : released) {
        owned_.erase(std::remove(owned_.begin(), owned_.end(), index), owned_.end());
    }
    report.complete = !failed;
    return report;
}

} // namespace pqvpn::routing
