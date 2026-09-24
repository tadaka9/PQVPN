# PQVPN Product Roadmap

PQVPN has completed its source-derived C++23 migration inventory, but it remains
experimental. This roadmap tracks the work required beyond migration parity.
Items are intentionally unchecked until implementation and verification
evidence are merged.

## Windows tunnel adapter — our own NDIS driver (no third-party drivers)

Policy: PQVPN ships its own signed tunnel driver for the Windows data path.
TAP-Windows6 (OpenVPN) and Wintun (WireGuard project) are transitional
backends only, not the destination. Design of record:
[`docs/windows-tunnel-adapter.md`](docs/windows-tunnel-adapter.md).

- [x] Phase 1 scaffold: WDK project + INF + `DriverEntry` (WDM) + default-deny file object; adapter visible under test signing, openable only by the node identity. *Status: implemented — compiles + links clean on x64 (valid PE32+ Native image, correct NDIS/Io imports); load verification pending test signing.*
- [x] Phase 2 data path + state machine + control channel: bounded ReadFile/WriteFile packet queues with backpressure and teardown drain; `WindowsOwnTunnel` backend behind the existing `Adapter` contract (*implemented*); VPN state machine (all states) owned by the node with kernel media up/down mirroring; external control channel `\\.\pipe\pqvpn-tun-ctl` (ACL-gated) exposing get_state/connect/disconnect + state_changed events; loopback ping through the adapter.
- [ ] Phase 3 integration + full control surface: full-tunnel mode end to end (default route + peer exclusions via `RouteTransaction`, two-node e2e, clean shutdown with route+DNS rollback) on a self-hosted Windows runner in the functional release gates; plus custom/transversal routes (add/remove/list/set — *implemented* via control channel), endpoint/startpoint config (*implemented*), custom IP enumeration (*implemented*), kill switch (fail-closed blackhole when down), and DNS switching with guaranteed restore-on-teardown — all externally callable via the control channel.
- [ ] Phase 4 hardening & signing: IRP fuzzing, HLK/DDI compliance, EV +
  Microsoft attestation pipeline, provenance attached to release packaging.

## Network and platform integration

Status notes (2026-09-20): the Windows route backend's root cause for
`CreateIpForwardEntry` failing with `ERROR_INVALID_PARAMETER` (87) is fixed —
`dwForwardProto` was left at zero instead of the required
`MIB_IPPROTO_NETMGMT` (`src/platform/windows_routes.cpp`). Transaction and
peer-exclusion logic pass their suites locally (72/72 CTest, `-j2`); live
verification on an elevated host with a connected adapter is still pending.

- [ ] Complete automatic peer selection for the Windows TAP data path.
- [ ] Install and remove Windows routes safely and transactionally —
  implementation + unit evidence exist; blocked on elevated end-to-end
  verification (see status note above).
- [ ] Complete bidirectional frame forwarding between TAP and encrypted peer
  transport.
- [ ] Validate shutdown, recovery, and adapter cleanup across supported Windows
  and Linux environments.

## Security assurance

- [ ] Publish a protocol-level threat model covering trust boundaries, traffic
  analysis, endpoint compromise, relay behavior, and denial-of-service limits.
- [ ] Commission an independent security review of the protocol and C++
  implementation.
- [ ] Resolve all findings that meet the project's release-blocking severity
  threshold.
- [ ] Add interoperability and known-answer coverage for externally observable
  protocol behavior where applicable.

## Release engineering

- [ ] Define supported operating systems, compilers, and dependency versions.
- [ ] Implement the ten `packaging/gates/<target>` native gate drivers required
  by `functional-release-gates.yml` (currently only `packaging/README.md`
  exists; the workflow refuses until they are present).
- [ ] Add reproducible release packaging with checksums and provenance.
- [ ] Exercise clean installation, upgrade, rollback, and removal procedures.
- [ ] Publish operator documentation for configuration, key lifecycle,
  observability, failure recovery, and incident response.

## Known issues (verification infrastructure)

- Local verification (2026-09-23, not yet merged): `pqvpn_hard_kernel` now
  explicitly caps its nested CTest at two workers and excludes the hardening
  label to prevent recursion. A regression checks the child command even with
  `CTEST_PARALLEL_LEVEL=64`. The full local suite passes (73/73, `--parallel 2`);
  this does not establish arbitrary outer-parallelism or native-driver safety.
- Local route hardening (2026-09-23, not yet merged): failed commit rollback
  attempts every newly installed route and retains failed removals for retry.
  Repeated commits and failed extensions preserve prior ownership. Three new
  regressions reproduce the old failures and pass with the fix. Elevated
  routing and adapter end-to-end verification remain pending.
- `functional-release-gates.yml` requires `packaging/gates/<target>` for ten
  targets; none exist yet — intentional fail-closed placeholder until release
  engineering lands (tracked above).

## Release criteria

The first production-oriented release must not be declared until:

- all applicable items above have merged evidence;
- the full CMake/CTest and hardening gates pass from a clean checkout;
- CodeQL reports no release-blocking findings; and
- the README's experimental warning can be revised based on documented audit
  and deployment evidence.

Migration history remains available in [`MIGRATE.md`](MIGRATE.md), with detailed
parity evidence in [`MIGRATION_MANIFEST.md`](MIGRATION_MANIFEST.md).
