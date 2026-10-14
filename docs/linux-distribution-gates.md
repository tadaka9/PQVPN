# Linux distribution artifact gates

PQVPN separates three independent checks:

1. **Artifact validation (implemented):** inspect the package bytes, target CPU,
   version, required payload, and (where supported) run a packaged executable.
   This is not a VPN release qualification.
2. **Native package lifecycle (incomplete):** install, upgrade, remove and
   verify service/configuration rollback on an isolated native distro runner.
3. **Native VPN/security qualification (incomplete):** signed packages and
   drivers, privileged tunnel end-to-end traffic, routing and DNS rollback,
   provenance, and exact-commit attestations.

Run locally after building a candidate:

```bash
python3 tools/verify-distribution-artifact.py \
  --target deb-x86_64 \
  --package artifacts/pqvpn_VERSION_amd64.deb \
  --version VERSION

python3 -m unittest discover -s tests/release -v
```

The verifier supports the nine Linux distribution targets in
`packaging/release-targets.json`:

| Target family | Artifact checks | Native production / lifecycle qualification |
|---|---|---|
| `linux-{x86_64,arm64}` | tar inventory, path safety, ELF machine | Privileged tunnel and rollback outstanding |
| `deb-{x86_64,arm64}` | dpkg metadata/version, extraction, node, safe launcher, smoke on matching host | Clean upgrade/removal, privileged network and signatures outstanding |
| `rpm-{x86_64,arm64}` | rpm name, exact prerelease, architecture, file inventory | Native RPM producer, Fedora/RHEL lifecycle and signing outstanding |
| `arch-x86_64` | .PKGINFO version/architecture and archive inventory | Native Arch builder, pacman lifecycle and signing outstanding |
| `appimage-{x86_64,arm64}` | ELF machine, native type-2 extraction, AppRun and node | Native AppImage producer, runtime/lifecycle and signing outstanding |

Current native CI executes the tar and DEB artifact gates on Linux x86_64
and ARM64. RPM, Arch and AppImage checks run when their corresponding native
artifacts and tooling exist; the release matrix **must not** treat the ability
to inspect a package as evidence of full lifecycle qualification.

The old `packaging/gates/linux-x86_64` is provisional. The other
`packaging/gates/<target>` implementations are not supplied by this change:
adding dummy scripts would misrepresent qualification. The strict
`tools/check-release-readiness.py` and both native qualified-publication
workflows remain fail-closed. A successful artifact check NEVER sets
`privileged_tunnel_e2e`, `platform_signature_verified` or any other native
evidence field to true. A signed release requires the native tests for the
exact commit and the protected attestation pipeline.

For native RPM and Arch lifecycle tests, provide genuine Fedora/RHEL and Arch
execution environments (container alone is not proof of privileged host VPN
operation); for ARM64 perform tests on an ARM64 host. AppImage needs its native
builder and sandbox-safe extraction. Windows and macOS have separate native
qualification requirements; this Linux gate does not replace them.
