#include "routing/route_transaction.hpp"

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

CommitReport RouteTransaction::commit(RouteBackend& backend) const {
    CommitReport report;
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        const auto result = backend.install(entries_[index]);
        if (!result.ok) {
            report.failed_index = index;
            report.error = result.error.empty() ? "route install failed" : result.error;
            // Roll back the installed prefix in reverse order. A rollback that
            // itself fails is recorded: the caller must treat the table as
            // uncertain and inspect it manually.
            for (std::size_t done = index; done-- > 0;) {
                const auto rollback = backend.remove(entries_[done]);
                if (!rollback.ok) {
                    report.error += "; rollback of an installed entry failed";
                    break;
                }
                report.rolled_back.push_back(entries_[done]);
            }
            return report;
        }
    }
    report.committed = true;
    return report;
}

RemovalReport RouteTransaction::remove_all(RouteBackend& backend) const {
    RemovalReport report;
    bool failed = false;
    for (const auto& entry : entries_) {
        const auto result = backend.remove(entry);
        if (!result.ok) {
            // Best-effort cleanup: record the first hard failure and keep
            // removing the remaining entries.
            if (!failed) {
                report.error = result.error.empty() ? "route removal failed" : result.error;
                failed = true;
            }
            continue;
        }
        if (result.not_found) {
            ++report.already_absent;
        } else {
            ++report.removed;
        }
    }
    report.complete = !failed;
    return report;
}

} // namespace pqvpn::routing
