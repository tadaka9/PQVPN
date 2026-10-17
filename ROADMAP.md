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
- [x] Phase 3 integration + full control surface: full-tunnel mode end to end (default route + peer exclusions via `RouteTransaction`, two-node e2e, clean shutdown with route+DNS rollback) on a self-hosted Windows runner in the functional release gates; plus custom/transversal routes (add/remove/list/set — *implemented* via control channel), endpoint/startpoint config (*implemented*), custom IP enumeration (*implemented*), kill switch routing (*implemented*), and DNS switching with guaranteed restore-on-teardown (*implemented*) — all externally callable via the control channel.
- [x] Phase 4 hardening & signing:
  - [x] HLK/DDI compliance test infrastructure (configuration, runner scripts, documentation)
  - [x] IRP fuzzing test suite
  - [x] EV code-signing certificate setup + Microsoft attestation pipeline (documentation and CI integration)
  - [x] Provenance attachment to release packaging (manifest generation/verification tools + CI integration)

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
- [x] Carry IPv4 and IPv6 through packet validation, peer routing and the
  user-space TCP/UDP egress bridge; fail closed when a full-tunnel client cannot
  protect IPv6.
- [x] Publish address-family state per mainnet peer instead of inferring IPv6
  reachability from binary capability. Helsinki is dual-stack; Stockholm stays
  IPv4-only until its provider supplies a global address and default route.
- [ ] Add an external authenticated IPv4/IPv6 handshake probe to the release
  gate and retain dated evidence for every advertised public endpoint.

## High-throughput data plane

- [x] Make Linux user-space TCP egress apply upstream backpressure instead of
  resetting long downloads when its bounded server buffer fills.
- [x] Negotiate TCP window scaling and use an adaptive tunnel congestion window:
  ACK-clocked growth for available high-bandwidth paths and multiplicative
  reduction on retransmission. The egress bridge now permits an 8 MiB flight,
  paces it in bounded event-loop batches and enforces a 64 MiB aggregate
  retained-payload budget across clients.
- [x] Preserve a strict per-flow memory ceiling while pausing and resuming
  upstream reads, so sustained download and upload performance does not trade
  away exit-node stability.
- [x] Replace the allocation-heavy nonce set with a bounded O(1) sliding
  replay bitmap: authenticate first, accept legitimate UDP reordering, reject
  duplicates and stale counters, and cap operator-configured replay memory.
- [x] Request larger bounded UDP socket buffers so short encrypted bursts are
  absorbed instead of discarded while user-space AEAD work is scheduled.
- [ ] Publish reproducible throughput, latency and loss benchmarks across the
  Helsinki–Stockholm mainnet path; report medians and percentiles rather than
  marketing maxima.
- [ ] Add paced packet batching and multi-queue processing only after profiling
  demonstrates a bottleneck, with fairness tests preventing one bulk transfer
  from starving interactive traffic.
- [ ] Replace per-packet linear session-hint lookup with a collision-aware,
  endpoint-bound index; benchmark lookup-flood resistance at the 4096-session
  limit.
- [ ] Evaluate Linux UDP GSO/GRO and reusable AEAD contexts behind capability
  checks; retain the portable path and prove identical wire output with
  known-answer and loss/reordering tests.

## Security assurance

- [x] Keep current StrangeNet groups decentralized without a group-key holder:
  require the complete pinned membership, encrypt independently through every
  member-contributed hybrid session, and test that ciphertext for one member
  cannot be used by another.
- [ ] Add scalable contributory group epochs only through a reviewed
  MLS/TreeKEM-compatible design with authenticated add/remove commits, epoch
  rotation, forward secrecy, post-compromise recovery, post-quantum combiner
  analysis, interoperability vectors and fail-closed downgrade handling. Do not
  replace the current hybrid pairwise fan-out with classical-only MLS.
- [ ] Publish a protocol-level threat model covering trust boundaries, traffic
  analysis, endpoint compromise, relay behavior, and denial-of-service limits.
- [ ] Commission an independent security review of the protocol and C++
  implementation.
- [ ] Resolve all findings that meet the project's release-blocking severity
  threshold.
- [ ] Add interoperability and known-answer coverage for externally observable
  protocol behavior where applicable.

## Asgard Cloud distributed storage

- [x] Implement a local encrypted multi-root core with 4 MiB chunks,
  per-chunk HKDF keys, AES-256-GCM, ciphertext addressing, rendezvous placement,
  atomic writes, replication quorum and hostile-manifest validation.
- [ ] Advertise storage capability with signed, expiring PQVPN records; node
  roles must never imply storage consent.
- [ ] Move encrypted chunks over authenticated PQVPN sessions with explicit
  quotas, backpressure and per-peer resource isolation.
- [ ] Implement local-only capacity samples and hysteresis-controlled scaling:
  warn at 60%, prepare one independent failure domain at 75%, fail closed for
  new writes above 85%, and never purchase or enroll capacity automatically.
- [ ] Add repair, garbage collection, encrypted metadata, key rotation and a
  user-controlled keystore integration.
- [ ] Evaluate erasure coding only after replication recovery is proven under
  loss, corruption, churn, disk-full and malicious-peer tests.
- [ ] Specify and implement a shared Asgard receipt ledger before enabling any
  credit purchase: consensus/finality, replay and double-spend resistance,
  idempotent payment intents, refund/chargeback handling and separate custody.
- [ ] Make credits non-transferable service units, keep VPN access independent
  of payment, and publish independently reconcilable allocation evidence for
  90% of net distributable proceeds to a named charity and 10% to PQVPN.
- [ ] Keep every purchase control fail-closed until the charity, jurisdiction,
  processor, fee denominator, terms and monthly accounting are configured and
  reviewed. Do not represent the current storage foundation as a blockchain.

## Release engineering

- [x] Define an ethical interaction-psychology standard for GUI, TUI, CLI,
  website and Pixel Commons; prohibit deceptive state and dark patterns.
- [ ] Add accessibility and state-feedback checks to each new interactive
  surface before release qualification.

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
  targets; none exist yet, so release publication remains fail-closed until release
  engineering lands (tracked above).

## Release criteria

The first production-oriented release must not be declared until:

- all applicable items above have merged evidence;
- the full CMake/CTest and hardening gates pass from a clean checkout;
- CodeQL reports no release-blocking findings; and
- the README's experimental warning can be revised based on documented audit
  and deployment evidence.

Historical migration artifacts were removed from the active tree because they
certified unused prototype modules. Git history retains them for archaeology.

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)
