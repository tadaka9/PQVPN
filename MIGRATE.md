# PQVPN C++23 Migration Status

## Migration complete

The source-derived migration inventory from the immutable Python reference
implementation in [`main.py`](main.py) has been completed.

| Measure | Result |
|---|---:|
| Inventoried units | 83 |
| Inventoried source weight | 4,362 lines |
| Completed source weight | 4,362 lines |
| Weighted migration completion | **100%** |

The authoritative per-contract evidence is maintained in
[`MIGRATION_MANIFEST.md`](MIGRATION_MANIFEST.md). It maps every inventoried
Python function or method to its C++ implementation and focused test evidence.
The chronological validation history is recorded in [`UPDATE.md`](UPDATE.md).

## What “complete” means

Migration completion means that every unit inventoried from `main.py` has an
accepted C++ parity contract and recorded test evidence under the project's
migration rules. It does **not** mean that PQVPN is production-ready, audited,
or suitable for protecting sensitive traffic.

The migration baseline must continue to satisfy:

- a clean CMake build;
- the registered CTest suite;
- the `pqvpn_hard_kernel` security gate;
- CodeQL analysis for C/C++ and Python; and
- the fail-closed cryptographic policy described in the README.

Regressions in any of these checks are release blockers, not new migration
work.

## Historical authority

- `main.py` remains the immutable behavioral specification for the completed
  migration inventory.
- `MIGRATION_MANIFEST.md` remains the weighted parity ledger and source of
  contract-level evidence.
- Future product work must not rewrite historical migration evidence merely to
  make completion metrics look better.

## Next phase

Outstanding engineering, security assurance, platform integration, and release
work is tracked separately in [`ROADMAP.md`](ROADMAP.md). This separation keeps
the completed migration record accurate while making unfinished product work
visible.
