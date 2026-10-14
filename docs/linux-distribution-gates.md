# Linux distribution artifact gates

PQVPN separates three independent checks:

1. **Artifact validation (implemented):** inspect the package bytes, target CPU,
   version, required payload, and trusted-native build correspondence when supplied.
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
| `linux-{x86_64,arm64}` | exact archive/root, safe members, full ELF64 program headers, match against smoke-tested native staging binary in CI | Privileged tunnel and rollback outstanding |
| `deb-{x86_64,arm64}` | dpkg metadata, filesystem TAR streaming without extraction, bounded ELF inspection, safe launcher | Clean upgrade/removal, privileged network and signatures outstanding |
| `rpm-{x86_64,arm64}` | rpm name, exact prerelease, architecture, file inventory | Native RPM producer, Fedora/RHEL lifecycle and signing outstanding |
| `arch-x86_64` | .PKGINFO version/architecture and archive inventory | Native Arch builder, pacman lifecycle and signing outstanding |
| `appimage-{x86_64,arm64}` | ELF64 header/program segments, embedded SquashFS superblock, read-only listing and bounded node inspection via unsquashfs | Native AppImage producer, runtime/lifecycle and signing outstanding |

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

The verifier never launches a binary from an inspected tar, DEB or AppImage. The AppImage reader does not run the AppImage with `--appimage-extract`; `unsquashfs -l/-cat -o OFFSET` reads its embedded filesystem without extraction into host paths. The DEB path streams `dpkg-deb --fsys-tarfile` into a Python TAR reader, rejecting traversal and malformed links. On Linux CI, the tar node must match the already smoke-tested CMake stage byte-for-byte. Read-only package parsers must still run in isolated CI environments when inspecting untrusted third-party content.

For native RPM and Arch lifecycle tests, provide genuine Fedora/RHEL and Arch
execution environments (container alone is not proof of privileged host VPN
operation); for ARM64 perform tests on an ARM64 host. AppImage needs its native
builder and sandbox-safe extraction. Windows and macOS have separate native
qualification requirements; this Linux gate does not replace them.
