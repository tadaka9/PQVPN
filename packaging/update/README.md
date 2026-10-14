# PQVPN update package

`*.pqvpnpkg` is a deterministic outer container for one native PQVPN package.
It does not replace MSI, DEB, PKG/DMG, AppImage, RPM, Arch packages, or their
platform signatures. It gives the Privacy Console one bounded format to verify
and extract after downloading a qualified GitHub Release.

The binary layout is:

1. ASCII magic `PQVPNPKG1` followed by a newline;
2. a four-byte big-endian JSON manifest length, limited to 64 KiB;
3. canonical UTF-8 JSON containing schema, product, version, release target,
   native payload name, size, SHA-256, and installation mode;
4. exactly one native package payload, limited to 1 GiB.

Release `SHA256SUMS` authenticates the complete outer container. The embedded
hash independently detects payload or manifest inconsistencies during
extraction. Paths, target names, payload type, exact length, and both hashes are
validated before a native package is committed to disk.

```bash
python3 packaging/update/build-package.py build \
  --payload PQVPN-version-windows-x64.msi \
  --version version --target windows-x86_64 \
  --output PQVPN-version-windows-x86_64.pqvpnpkg

python3 packaging/update/build-package.py verify \
  PQVPN-version-windows-x86_64.pqvpnpkg
```
