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

As of version 0.0.9-10152026-David0-beta-OTA, PQVPN does **not** have 13 fully qualified native release drivers. The existing Linux x86_64 script is a build/smoke prototype; it explicitly leaves seven required functional/signature/provenance checks unverified and now exits nonzero with passed:false. Twelve other target drivers are missing.

macOS requires actual signed/notarized packages, Apple Silicon and Intel lifecycle/tunnel tests; Windows requires signed/qualified drivers and install/rollback testing, plus a configured native Windows ARM64 release runner. RPM, Debian, Arch and AppImage require real per-architecture, distro-native package, privileged traffic, rollback, signature and provenance evidence, not just artifact inspection. Signing keys and protected release environments must be provisioned outside these source changes.

Until those native dependencies exist and are tested, **qualified release publication must remain blocked**. The source/runner fixes here improve correct diagnosis and verification, not the unperformed native tests.
