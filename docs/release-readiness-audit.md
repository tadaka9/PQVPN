# Prerelease build and packaging audit — 14 October 2026

Scope: Linux development workflow, release packaging/runtime regression,
publication controls, and native qualification prerequisites. This is not an
independent cryptographic security audit or evidence that every platform works.

## Corrections implemented

- `PQVPN_VERSION.txt` now selects the unused version
  `0.0.6-alpha-14102026-David0`. Existing releases/tags are preserved.
- CLI version and CPack version derive from that file, including the prerelease
  suffix. A CTest regression covers CLI version output.
- Debian packaging retains the CMake deployment tree under `/usr/lib/pqvpn`,
  including matching Qt libraries, plugins, and `qt.conf`; relative launchers
  live under `/usr/bin`. System dependencies are computed from shipped ELF
  objects with `dpkg-shlibdeps`. Bundled SONAMEs do not create self-dependencies.
- Optional deployment trees are matched to build artifacts by ELF build IDs,
  which survive CMake's install-RPATH rewriting. Package permissions no longer
  depend on the invoking shell's umask.
- Linux CMake installation includes the offscreen platform plugin when the Qt
  package exports it. CI tests the installed tar staging tree and extracted
  Debian GUI with external Qt loader/plugin search overrides removed.
- Tag-triggered CI no longer publishes smoke-only assets. Qualified publication
  remains the only publication path and still requires trusted native evidence,
  signatures, and verified artifact attestations.
- `packaging/release-targets.json` records the thirteen mandatory qualification
  targets. Source preflight reports all missing/non-executable/provisional gates
  and validates tag/version/commit agreement before release jobs consume runners.
- The provisional Linux gate is executable. Its false assertions remain false;
  those checks have not been implemented or verified.
- RPM/Arch are included in the gate matrix and publication validation, preserving
  all thirteen formats required by the packaging contract. Service configuration
  requires an explicit reviewed operator configuration; packages do not
  automatically join the public bootstrap peer.

## Local verification

- GCC 14.2, CMake 3.31.10, Ninja 1.13.0; pinned OpenSSL 4.0.3,
  Argon2 20190702, and liboqs 0.16.0.
- Debug build and 68/68 CTests passed, including the security hardening gate,
  hybrid handshake tests, and encrypted two-node local HTTP egress.
- Five source-preflight regression tests passed: missing gate, non-executable
  gate, provisional false assertion, invalid target/path, and duplicate target.
- CLI-only Debian package built; dependency metadata contains actual libc/libgcc/
  libstdc++ constraints rather than the previous guessed OpenSSL requirement.
- GUI packaging regression: the published Linux GUI/Qt 6.10.2 deployment,
  whose checksum had been verified, was packaged with the fixed CLI/TUI and a
  matching official Qt 6.10.2 offscreen plugin from PySide6-Essentials.
  The extracted Debian GUI completed offscreen smoke and generated an image.
  No system Qt replacement or TLS/checksum bypass was used.
- That regression verifies deployment/layout and dependency resolution. It does
  not claim the current main GUI was rebuilt locally against its pinned Qt 6.12;
  the native CI checks perform that build and package smoke test.
- Modified workflow YAML parses, mandatory manifest agrees with the native job
  matrix, shell syntax/whitespace checks pass, and attribution policy passes.

## Remaining qualified-release blockers

1. Twelve actual native gate implementations are still absent: macOS ARM64/x64,
   Windows ARM64/x64, Linux ARM64, AppImage ARM64/x64, Debian ARM64/x64,
   RPM ARM64/x64, and Arch x64.
2. The existing Linux x64 script builds and smoke-tests only. It explicitly
   leaves privileged tunnel traffic, bidirectional traffic, route/DNS rollback,
   clean install/upgrade/remove, runtime validation, platform signature, and
   provenance validation unverified. Source preflight rejects it.
3. This machine has no `/dev/net/tun`; privileged system VPN and package lifecycle
   qualification cannot be executed here. Other OS/architecture tests require
   their native hosts and the application's supported platform integrations.
4. GitHub API read access now works. Runner/secret administration endpoints return
   `Resource not accessible by integration`; configured runner labels and signing
   bindings cannot be inspected with this integration. At inspection time the
   environment list did not contain either of the two named release
   environments. The existing CI GitHub-hosted runner labels are reused for matching targets;
   Windows ARM64 remains outside that baseline and requires a native runner.
   Protected signing/release environments must be configured and verified
   before qualification.
5. Existing version `v0.0.5-alpha-10092026-David0` points to an older commit and
   is already published. The replacement version is staged in source; no new
   release/tag should be created until reviewed fixes and native qualification
   succeed for the exact immutable commit.

Do not turn false flags into true, add passing placeholder gate scripts, reuse
old-commit artifacts, or disable mandatory platform checks to publish. The
source preflight is deliberately still failing until genuine native evidence
can be produced. These fixes improve packaging and prevent premature publication;
they do not make a qualified multi-platform prerelease ready.

## Extended installer and console audit

The user additionally requested all installer/package paths and refinement of
GUI/TUI behavior. These changes add:

- A shared, tested connection-state model. Gray is disconnected, amber is
  connecting/securing/disconnecting, green is an authenticated relay or a
  protected tunnel, and red is failure. A running process alone is insufficient.
- A programmatically rendered tray icon, including high-DPI sizes, avoiding an
  extra SVG loader requirement for status colors. GUI smoke checks icon colors.
- A smaller overview with live configuration/peer/protection checklist and one
  primary configure/connect/disconnect action. Dark/light preferences remain.
- A resize-aware TUI with verification and mode shortcuts, authenticated event
  parsing, bounded line buffering, terminal-control sanitization, direct argv
  process launch, and terminal-state restoration. Relay mode is explicit.
- Writable per-user default configurations for installed consoles. Existing
  user edits are preserved; installed example files are never edited.
- A udp2raw attach-profile action that coordinates an existing loopback listener,
  reuses an existing engine configuration path, and retains engine credentials
  in that engine's file. It does not install/start a raw-socket engine or claim
  Shadowsocks/V2Ray/obfs4 integration, which still requires transport adapters.
- Configuration normalization now preserves WireGuard/OpenVPN backend selections
  even when an interface name was not supplied.
- Windows portable packaging fails when GUI deployment tools are absent; packaged
  launchers select their own directory. A three-component MSI version replaces
  the ineffective fourth date component that Windows ignores for upgrades.
- Native Windows package tests exercise ZIP runtime, real MSI clean install,
  upgrade from the existing checksum-verified prerelease, and removal.
- macOS uses a real application bundle with paired node and configuration examples.
  Native checks run the installed application without SDK loader overrides.
- Arch dependencies follow pinned upstream minimum versions, and its system-Qt
  installation disables private deployment to avoid global Qt runtime collisions.

| Format / architecture | Packaging path | Checks and limits |
|---|---|---|
| Linux tar, x64/ARM64 | native CMake deployment + tar | Installed CLI/GUI runtime smoke on native CI; system install/remove and privileged tunnel gate still missing |
| Debian, x64/ARM64 | custom complete-runtime builder | Extracted runtime, version, configuration, and dependency checks; clean distro install/upgrade/remove gate still missing |
| Windows x64 ZIP | windeployqt portable builder | Extracted CLI/TUI/GUI runtime checks without SDK Qt PATH; no kernel driver payload |
| Windows x64 MSI | WiX v3 per-machine installer | Native clean install/upgrade/remove tests added; signing and privileged tunnel qualification remain required |
| macOS Intel/ARM64 archive | deployed application bundle + tar | Installed application runtime checks added; Developer ID signing/notarization and native tunnel gate remain required |
| Windows ARM64 ZIP/MSI | no reviewed native producer/gate | Unsupported by current native CI baseline; not claimed verified |
| AppImage x64/ARM64 | no producer/gate implemented | Not produced or verified; native package workflow must be implemented |
| RPM x64/ARM64 | generic CPack capability only | No native RPM distribution producer/lifecycle evidence; not claimed verified |
| Arch x64 | generated checksum-pinned PKGBUILD | Recipe/version/dependency checks; makepkg and native installation not executed here |

Native CI for earlier commit `8e05464` passed all five build jobs, both hardening/
Windows-driver jobs, attribution policy, and both CodeQL analyses. The extended
installer/console changes require their own fresh native run; consult PR checks
for the current commit rather than reusing that earlier result.

SSH inspection/deployment remains blocked: the requested `C:\Users\dvx3\.ssh`
folder belongs to the user's Windows PC and is not mounted in this Linux cloud
machine. Neither requested alias is configured here; key/agent bindings are
absent. User permission to read that directory does not transfer its contents.
No remote server was logged into or changed, and no private key was printed.
