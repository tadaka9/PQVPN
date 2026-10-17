#!/bin/bash
set -euo pipefail
umask 022

VERSION="${1:-$(tr -d '[:space:]' < PQVPN_VERSION.txt)}"
OUTPUT="$(realpath -m "${2:-artifacts}")"
BINARY="${3:-dist/pqvpn-flux}"
ARCH="$(dpkg --print-architecture)"
test "$ARCH" = amd64
test -x "$BINARY"
file -b "$BINARY" | grep -q '^ELF 64-bit LSB.*x86-64'

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
install -d "$ROOT/DEBIAN" "$ROOT/usr/bin" "$ROOT/usr/share/doc/pqvpn-flux"
install -m 0755 "$BINARY" "$ROOT/usr/bin/pqvpn-flux"
cat > "$ROOT/DEBIAN/control" <<EOF
Package: pqvpn-flux
Version: ${VERSION//-/'~'}
Architecture: amd64
Maintainer: tadaka9 <tadaka9@users.noreply.github.com>
Depends: openssh-client
Section: net
Priority: optional
Homepage: https://github.com/tadaka9/PQVPN
Description: Privacy-preserving local fleet console for PQVPN
 Displays only aggregate service health and machine resource metrics over the
 operator's existing SSH aliases. It does not collect peer addresses, peer IDs,
 keys, logs, payloads, or browsing data, and sends no telemetry.
EOF
cat > "$ROOT/usr/share/doc/pqvpn-flux/README" <<'EOF'
Run: pqvpn-flux
Requires working SSH aliases named AEwarness and Awarness.
The console is read-only and uses no forwarding. All output remains local.
EOF
mkdir -p "$OUTPUT"
dpkg-deb --build --root-owner-group "$ROOT" "$OUTPUT/pqvpn-flux_${VERSION}_amd64.deb"
