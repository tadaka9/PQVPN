# PQVPN Product Roadmap

PQVPN has completed its source-derived C++23 migration inventory, but it remains
experimental. This roadmap tracks the work required beyond migration parity.
Items are intentionally unchecked until implementation and verification
evidence are merged.

## Network and platform integration

- [ ] Complete automatic peer selection for the Windows TAP data path.
- [ ] Install and remove Windows routes safely and transactionally.
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
- [ ] Add reproducible release packaging with checksums and provenance.
- [ ] Exercise clean installation, upgrade, rollback, and removal procedures.
- [ ] Publish operator documentation for configuration, key lifecycle,
  observability, failure recovery, and incident response.

## Release criteria

The first production-oriented release must not be declared until:

- all applicable items above have merged evidence;
- the full CMake/CTest and hardening gates pass from a clean checkout;
- CodeQL reports no release-blocking findings; and
- the README's experimental warning can be revised based on documented audit
  and deployment evidence.

Migration history remains available in [`MIGRATE.md`](MIGRATE.md), with detailed
parity evidence in [`MIGRATION_MANIFEST.md`](MIGRATION_MANIFEST.md).
