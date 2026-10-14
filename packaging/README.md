# PQVPN release packaging contract

This directory defines the release contract; it does not claim that PQVPN is
currently a functional system VPN on every target. Packaging is permitted only
after a privileged, native end-to-end gate has produced evidence for the exact
commit and target being released.

## Required targets

All thirteen required publication targets are listed in `release-targets.json`.
The native gate matrix and publication count include RPM and Arch as well as
macOS, Windows, Linux tar archives, AppImage, and Debian packages. Each format
requires its own real installation/lifecycle evidence; build-only artifacts
are insufficient.

| Target ID | Runner/build architecture | Expected package |
|---|---|---|
| `macos-arm64` | macOS ARM64 | signed and notarized archive or installer |
| `macos-x86_64` | macOS Intel | signed and notarized archive or installer |
| `windows-arm64` | Windows ARM64 | Authenticode-signed ZIP or MSI |
| `windows-x86_64` | Windows x64 | Authenticode-signed per-machine MSI (required); portable ZIP may be published additionally |
| `linux-arm64` | Linux ARM64 | tar archive |
| `linux-x86_64` | Linux x64 | tar archive |
| `appimage-arm64` | Linux ARM64 | AArch64 AppImage |
| `appimage-x86_64` | Linux x64 | x86-64 AppImage |
| `deb-arm64` | Debian-compatible ARM64 | `.deb` (`Architecture: arm64`) |
| `deb-x86_64` | Debian-compatible x64 | `.deb` (`Architecture: amd64`) |
| `rpm-arm64` | RPM-compatible ARM64 | `.rpm` (`Architecture: aarch64`) |
| `rpm-x86_64` | RPM-compatible x64 | `.rpm` (`Architecture: x86_64`) |
| `arch-x86_64` | Arch Linux x64 | package built from `packaging/arch/PKGBUILD` |

The current native Linux workflow produces tar archives and `.deb` artifacts
for both architectures. RPM and AppImage producers/lifecycle gates remain to be
implemented. Arch Linux users can generate a checksum-pinned PKGBUILD with
`packaging/arch/generate-pkgbuild.sh COMMIT OUTPUT` and build using `makepkg -si`;
a native Arch packaging job has not yet verified this path.

`PQVPN_VERSION.txt` is the single package-version source. Changing it updates CMake,
DEB, RPM, and the generated PKGBUILD in the next workflow. A `v*` tag runs build
and source readiness checks. Publication uses `Publish qualified prerelease`
only after native functional qualification.

The Windows x64 MSI is a mandatory release asset. The portable ZIP is a
separate convenience package and never substitutes for the installer. The MSI
contains the node, terminal console, native GUI, Qt runtime, and configuration.
A kernel-driver payload may only be added by the qualified signing pipeline;
an unsigned driver must never be smuggled into the installer.

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

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)

## Prepare and qualify a new immutable release

Never move an existing tag or replace the bytes of a published version.
Update `PQVPN_VERSION.txt` to an unused prerelease version and merge fixes
only after the native CI matrix and hardening tests pass. Run
`python3 tools/check-release-readiness.py` before creating the version tag.
This command lists missing/provisional drivers; it does not certify native
behavior. The current Linux driver is provisional and the other twelve drivers
still require implementation.

Create the tag at the reviewed commit, then dispatch `Native functional release
gates` using that tag as both the workflow ref and the `tag` input. The five existing CI platform runner choices are reused for matching targets.
Windows ARM64 still needs a native runner because it is outside that baseline.
Each native runner must actually build/sign, exercise bidirectional privileged tunnel
traffic, restore route/DNS state, and test clean installation, upgrade, and
removal. Missing tests must fail the gate; never change false evidence to true
without the corresponding test. `Publish qualified prerelease` accepts only a
successful matching-commit evidence run and verifies candidate attestations.

## Debian runtime and service configuration

`build-package.sh BUILD_DIR OUTPUT_DIR VERSION [DEPLOYED_INSTALL_TREE]` uses
CMake's full deployment tree. Executables, Qt libraries, plugins, and `qt.conf`
remain together under `/usr/lib/pqvpn`; relative launchers live in `/usr/bin`.
An optional install tree must match the build's ELF build IDs. System library
dependencies are generated by `dpkg-shlibdeps`, including plugin dependencies;
bundled Qt is not replaced by an older distribution Qt. Linux deployment also
includes the offscreen plugin when available so CI can test extracted packages.

Packages deliberately install configuration examples without starting a VPN.
Before enabling `pqvpn.service`, copy `/etc/pqvpn/config.json.example` to
`/etc/pqvpn/config.json`, review its listen address and bootstrap peer list,
then run `pqvpn_node --validate-config --config /etc/pqvpn/config.json`.
No operator configuration is silently overwritten during upgrades. Privileged
service lifecycle qualification remains a native release gate requirement.


Windows package CI exercises portable runtime plus MSI clean installation,
upgrade, and removal on a disposable native runner. MSI ProductVersion uses
three numeric components; Windows ignores a fourth component for upgrade
ordering. Every published prerelease must use an unused numeric base version.
These installer tests do not establish kernel-driver signing or full VPN
qualification. macOS archives now contain a paired application bundle; Developer
ID signing and notarization remain separate mandatory release gates.

Installed GUI/TUI consoles prepare a private writable user profile when launched
without a configuration and an installed example exists. They preserve existing
user profiles and never modify the installed template. GUI transport presets
keep keys in the external engine's configuration and only prepare supported
loopback UDP attachment; TCP/SOCKS adapters remain unimplemented.
