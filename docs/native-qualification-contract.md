# PQVPN native release qualification contract — schema 2

Qualified publication is separate from the green cross-platform build CI and the explicitly unsigned, unqualified test beta.

## Launch from an immutable tag

After reviewed code has been merged, create a new unused version tag at its exact commit, and dispatch **Native functional release gates** using that **tag ref**, not the default branch ref. Example CLI command:

    gh workflow run functional-release-gates.yml --ref "$TAG" -f tag="$TAG"

The source-integrity job checks the tag's peeled commit against checkout HEAD, the version label, and the complete mandatory set of **13** targets. Missing native gate implementations are reported, but do not prevent the other independent native gate jobs from running. Each target must succeed separately. When all 13 gates have real evidence and successfully attested candidates, dispatch **Publish qualified prerelease** from that same tag ref with the exact successful functional run ID.

The --integrity-only switch affects only the source preflight: it does not exempt any native target or make a release qualified. The default readiness command remains strictly fail-closed when mandatory native drivers are missing or explicitly unverified.

## Native driver output

The executable packaging/gates/TARGET must perform actual privileged tunnel and bidirectional traffic tests, routing/DNS rollback, clean install/upgrade/removal, runtime dependency checks, code signing, and exact source provenance validation. It must fail on any unverified requirement.

Under PQVPN_OUTPUT_DIR, create:
- verification.log: a nonempty log of the real operations, with no secrets;
- candidate/: exactly one native signed package (never a dummy);
- evidence.json: schema 2 with exact content hashes of both the candidate and the log.

Evidence fields: schema (integer 2), target, commit_sha, version, candidate_name, candidate_size, candidate_sha256, verification_log_sha256, runner_os, runner_arch. Every following field must be the **JSON boolean true** only when the corresponding native test really passed: passed, native_runner, privileged_tunnel_e2e, bidirectional_traffic, route_dns_rollback, clean_install_upgrade_remove, architecture_verified, runtime_dependencies_verified, platform_signature_verified, provenance_verified.

The validator requires an exact 40-digit SHA-1 commit identifier from the tag, full SHA-256 hashes of the candidate and log, agreement with source version and target/architecture, and true booleans (not strings or numbers). The native workflow also binds reported OS/architecture to the runner's actual GitHub context. The publisher checks the candidate bytes again and verifies its independent GitHub build-provenance attestation.

The verifier does not execute a package and cannot by itself prove that a self-reported functional test ran. Assurance requires reviewed native test code, protected trusted runners, valid platform signatures, and build-provenance attestations for the exact candidate and run. Manually setting the flags to true is not sufficient.

## Remaining prerequisites

As of version 0.0.9-10152026-David0-beta-OTA, PQVPN does **not** have 13 fully qualified native release drivers. Linux x86_64 and ARM64 now have executable partial native drivers that compile the genuine node, run a named set of user-space encrypted egress/dataplane and route-transaction tests, validate the ELF architecture, check host library loading, and verify the staged tarball against the compiled executable. They emit schema-2 evidence with `passed: false` and all unperformed native/signing/provenance requirements explicitly false, and exit nonzero. **Eleven** other platform/distro qualification drivers remain absent.

macOS requires actual signed/notarized packages, Apple Silicon and Intel lifecycle/tunnel tests; Windows requires signed/qualified drivers and install/rollback testing, plus a configured native Windows ARM64 release runner. RPM, Debian, Arch and AppImage require real per-architecture, distro-native package, privileged traffic, rollback, signature and provenance evidence, not just artifact inspection. Signing keys and protected release environments must be provisioned outside these source changes.

Until those native dependencies exist and are tested, **qualified release publication must remain blocked**. The source/runner fixes here improve correct diagnosis and verification, not the unperformed native tests.

## Diagnostic prerequisite probe (13 native targets)

The protected native job runs `tools/verify-native-gate-environment.py`
before any functional gate. It detects the actual runner OS/CPU, elevated
privileges, a Linux TUN character device, and available per-platform signing
and packaging tools; a machine-readable `host-prerequisites.json` is
preserved with other diagnostic artifacts on failure. Ten unprivileged mock
regressions verify fail-closed behavior for wrong CPU/OS, missing TUN,
unprivileged execution, missing native packaging/signing tools, and that a
passing host probe **never** represents qualification. A host with the right
tools still needs the actual tunnel/lifecycle/signing/provenance tests.

The Linux gate uses Catch2's `test_e2e_egress`,
`test_tunnel_dataplane` and `test_route_transaction` against actual compiled
source and packages the node with an exact release version/root. The egress
test uses a **scripted adapter**, not a privileged host TUN, and route tests
use a **scripted backend**: neither can set `privileged_tunnel_e2e`,
`bidirectional_traffic`, or `route_dns_rollback` true. Runtime link
inspection on a single build host does not count as a clean distro
installation. The checks provide genuine partial regression coverage, not
qualified-release evidence.

To complete qualification each target still requires its reviewed native
kernel/network tests, isolated system-state rollback and package lifecycle,
trusted signing identity and verification, and immutable attestations.
Signing keys, notarization, Windows ARM64 hardware/driver pipeline and
native distro environments cannot be manufactured by a source commit.
