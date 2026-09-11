#ifndef PQVPN_ROUTE_TRANSACTION_HPP
#define PQVPN_ROUTE_TRANSACTION_HPP

#include <asio.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pqvpn::routing {

/**
 * @brief One routing-table entry: a destination prefix with its next hop.
 *
 * `interface_index` is the OS interface that owns the gateway (0 lets a
 * backend resolve it from the gateway address). Entries are applied in the
 * order they were added to a RouteTransaction.
 */
struct RouteEntry {
    asio::ip::address prefix;
    std::uint8_t prefix_length = 0;
    asio::ip::address gateway;
    std::uint32_t interface_index = 0;

    [[nodiscard]] bool valid() const noexcept {
        return prefix.is_unspecified() == false &&
               gateway.is_unspecified() == false &&
               prefix_length <= (prefix.is_v4() ? 32 : 128);
    }
};

/**
 * @brief Outcome of one backend operation.
 *
 * `ok` means the desired state was reached: installed, or already present on
 * install; removed, or already absent on remove. Informational flags describe
 * which case applied; `error` carries detail only when ok is false.
 */
struct OperationResult {
    bool ok = false;
    bool already_present = false; // install found the entry in place beforehand
    bool not_found = false;       // remove found no such entry (idempotent success)
    std::string error;
};

/**
 * @brief Platform seam over the OS routing table.
 *
 * Implementations must be safe for sequential use from one thread at a time.
 */
class RouteBackend {
public:
    virtual ~RouteBackend() = default;

    virtual OperationResult install(const RouteEntry& entry) = 0;
    virtual OperationResult remove(const RouteEntry& entry) = 0;
};

/**
 * @brief Outcome of a transactional commit.
 */
struct CommitReport {
    bool committed = false;      // true only when every entry was installed
    std::size_t failed_index = 0; // first entry that could not be installed
    std::vector<RouteEntry> rolled_back; // entries removed during rollback, reverse order
    std::string error;          // backend detail for the failing install
};

/**
 * @brief Outcome of an idempotent removal pass.
 */
struct RemovalReport {
    std::size_t removed = 0;        // entries confirmed removed by the backend
    std::size_t already_absent = 0; // entries that were not present
    bool complete = false;          // no hard failures during cleanup
    std::string error;              // detail of the first hard failure, if any
};

/**
 * @brief All-or-nothing batch of routing-table changes.
 *
 * commit() installs every entry in plan order and rolls back the installed
 * prefix (reverse order) when an install fails, so a partial route set never
 * survives. remove_all() cleans up best-effort: it keeps going past a hard
 * failure so shutdown always attempts to leave no routes behind.
 */
class RouteTransaction {
public:
    void add(RouteEntry entry);

    [[nodiscard]] const std::vector<RouteEntry>& entries() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

    CommitReport commit(RouteBackend& backend) const;
    RemovalReport remove_all(RouteBackend& backend) const;

private:
    std::vector<RouteEntry> entries_;
};

} // namespace pqvpn::routing

#endif
