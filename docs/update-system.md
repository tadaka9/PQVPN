# Release update system

PQVPN has two release consumers with different authority boundaries.

The Privacy Console provides a manual desktop flow. **About → Check releases**
queries the public GitHub Releases API only after the user requests it. The
console ignores drafts, compares release tags with the compiled public version,
and chooses an asset for the current operating system and CPU architecture. It
prefers `*.pqvpnpkg`, then falls back to the platform's native release asset for
compatibility with older releases.

A desktop download is accepted only when the same release contains
`SHA256SUMS` with exactly one entry for that asset. The response and download
have time and size limits, redirects may not reduce transport security, and the
asset URL must originate under this repository's GitHub release path. Downloads
are written atomically under the user's `PQVPN-updates` folder.

For `*.pqvpnpkg`, the console also validates the bounded manifest, release
version, platform target, native filename, installation mode, exact payload
length, and embedded SHA-256. It atomically extracts the original MSI, DEB, or
macOS package and opens the containing folder. It does not execute the package,
request elevation, stop a connection, or alter routes. Native package signing
and the qualified release gates remain mandatory.

The headless Linux mainnet updater has a separate operational role. It verifies
that exactly one architecture archive and checksum list exist, selects the
highest comparable release, refuses rollback below `current-version`, pins both
download URLs to the exact repository and tag, and requires one unique checksum
for the asset. It then validates the existing production configuration with the
candidate node, stages a versioned installation, switches an atomic `current`
symlink, restarts the service, observes stability, and rolls back the symlink
and service if the candidate fails. Its setup is documented in
[mainnet-operations.md](mainnet-operations.md).

Maintainers create custom containers with
`packaging/update/build-package.py`. The qualified publication workflow wraps
each already attested native candidate, verifies every container, generates
release checksums over native and custom packages, and refuses to modify an
existing release. Format details are in
[`packaging/update/README.md`](../packaging/update/README.md).

Current limits:

- checksums provide integrity and release-byte binding; they do not replace
  Authenticode, Developer ID/notarization, distribution signatures, or release
  provenance;
- the Linux updater is anti-rollback only while its root-owned install state is
  trustworthy; production release signing still needs an offline signing key;
- the desktop flow stages an installer and leaves installation to the user;
- release publication remains blocked until all thirteen native functional
  gates and signing requirements are implemented and pass for the exact tag.

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)
