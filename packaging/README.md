# PQVPN release packaging contract

This directory defines the release contract; it does not claim that PQVPN is
currently a functional system VPN on every target. Packaging is permitted only
after a privileged, native end-to-end gate has produced evidence for the exact
commit and target being released.

## Required targets

| Target ID | Runner/build architecture | Expected package |
|---|---|---|
| `macos-arm64` | macOS ARM64 | signed and notarized archive or installer |
| `macos-x86_64` | macOS Intel | signed and notarized archive or installer |
| `windows-arm64` | Windows ARM64 | Authenticode-signed ZIP or MSI |
| `windows-x86_64` | Windows x64 | Authenticode-signed ZIP or MSI |
| `linux-arm64` | Linux ARM64 | tar archive |
| `linux-x86_64` | Linux x64 | tar archive |
| `appimage-arm64` | Linux ARM64 | AArch64 AppImage |
| `appimage-x86_64` | Linux x64 | x86-64 AppImage |
| `deb-arm64` | Debian-compatible ARM64 | `.deb` (`Architecture: arm64`) |
| `deb-x86_64` | Debian-compatible x64 | `.deb` (`Architecture: amd64`) |

An AppImage still requires the tunnel and routing privileges needed by a VPN.
It must not use setuid. Debian packages must document and test their service,
capability, configuration, upgrade, rollback, and removal behavior.

macOS packages require Developer ID signing, hardened-runtime entitlements,
notarization, and stapling. Windows packages and any tunnel driver require
valid platform signatures; the project must never redistribute an unsigned
driver. Signing credentials belong in a protected GitHub environment and must
never be exposed to pull requests.

## Functional evidence artifact

For every target, a trusted native test workflow must upload an artifact named
`functional-evidence-<target-id>` containing `evidence.json`. The same workflow
must upload the corresponding package as `release-candidate-<target-id>`.

`evidence.json` must contain:

```json
{
  "schema": 1,
  "target": "linux-x86_64",
  "commit_sha": "40 hexadecimal characters",
  "passed": true,
  "native_runner": true,
  "privileged_tunnel_e2e": true,
  "bidirectional_traffic": true,
  "route_dns_rollback": true,
  "clean_install_upgrade_remove": true,
  "architecture_verified": true,
  "runtime_dependencies_verified": true,
  "platform_signature_verified": true,
  "provenance_verified": true
}
```

The release workflow validates every field and refuses publication when any
artifact or assertion is absent. Assertions are a transport format, not a
substitute for the native tests that create them. Each candidate must also have
a GitHub artifact attestation tied to this repository.

## Publication output

The trusted evidence workflow is responsible for producing final, signed
candidates. The publication workflow downloads those exact bytes, verifies
their attestations, writes `SHA256SUMS`, and creates a GitHub prerelease. Moving
a version to a production release additionally requires the project's security
and product release criteria.
