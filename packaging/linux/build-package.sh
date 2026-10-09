#!/bin/bash
# PQVPN Linux package builder (DEB)
# Produces a policy-compliant .deb with binaries under /usr/bin,
# configuration examples under /etc/pqvpn, the systemd unit under
# /usr/lib/systemd/system, and the desktop entry under /usr/share.

set -euo pipefail

BUILD_DIR="${1:-build}"
OUTPUT_DIR="${2:-artifacts}"
VERSION="${3:-0.0.0}"

if [ ! -f "$BUILD_DIR/pqvpn_node" ]; then
    echo "error: $BUILD_DIR/pqvpn_node not found" >&2
    exit 1
fi

ARCH="$(dpkg --print-architecture)"
PKG_ROOT="$OUTPUT_DIR/pqvpn-$VERSION/deb-root"
DEB_FILE="$OUTPUT_DIR/pqvpn_${VERSION}_${ARCH}.deb"

echo "Building PQVPN deb package"
echo "  build dir: $BUILD_DIR"
echo "  output:    $DEB_FILE"
echo "  arch:      $ARCH"

rm -rf "$PKG_ROOT"
mkdir -p \
    "$PKG_ROOT/DEBIAN" \
    "$PKG_ROOT/usr/bin" \
    "$PKG_ROOT/etc/pqvpn" \
    "$PKG_ROOT/usr/share/pqvpn" \
    "$PKG_ROOT/usr/lib/systemd/system" \
    "$PKG_ROOT/usr/share/applications" \
    "$PKG_ROOT/usr/share/icons/hicolor/256x256/apps"

install -m 0755 "$BUILD_DIR/pqvpn_node" "$PKG_ROOT/usr/bin/"
install -m 0755 "$BUILD_DIR/pqvpn_tui" "$PKG_ROOT/usr/bin/"
if [ -f "$BUILD_DIR/pqvpn_monitor" ]; then
    install -m 0755 "$BUILD_DIR/pqvpn_monitor" "$PKG_ROOT/usr/bin/"
fi

install -m 0644 config.json "$PKG_ROOT/etc/pqvpn/config.json.example"
install -m 0644 config.udp2raw.json "$PKG_ROOT/etc/pqvpn/config.udp2raw.json.example"
install -m 0644 README.md LICENSE "$PKG_ROOT/usr/share/pqvpn/"

if [ -f "packaging/linux/pqvpn.service" ]; then
    install -m 0644 packaging/linux/pqvpn.service "$PKG_ROOT/usr/lib/systemd/system/"
else
    cat > "$PKG_ROOT/usr/lib/systemd/system/pqvpn.service" << 'EOF'
[Unit]
Description=PQVPN Post-Quantum VPN Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/pqvpn_node --config /etc/pqvpn/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
fi

if [ -f "$BUILD_DIR/pqvpn_monitor" ] && [ -f "packaging/linux/pqvpn-monitor.desktop" ]; then
    install -m 0644 packaging/linux/pqvpn-monitor.desktop "$PKG_ROOT/usr/share/applications/"
fi

cat > "$PKG_ROOT/DEBIAN/control" << EOF
Package: pqvpn
Version: $VERSION
Architecture: $ARCH
Maintainer: PQVPN <noreply@pqvpn.invalid>
Depends: libc6, libstdc++6, libssl3t64 | libssl3
Section: net
Priority: optional
Homepage: https://tadaka9.github.io/PQVPN/
Description: Post-quantum VPN node with ML-KEM-1024 key exchange
 PQVPN is an experimental post-quantum VPN that pairs classical
 encryption with ML-KEM-1024 and ML-DSA-87 signatures.
 .
 This package installs the node daemon (pqvpn_node), the terminal
 console (pqvpn_tui), and the Qt privacy console when available.
EOF

dpkg-deb --build --root-owner-group "$PKG_ROOT" "$DEB_FILE"
rm -rf "$PKG_ROOT"
dpkg-deb --info "$DEB_FILE" > /dev/null
echo "Debian package created: $DEB_FILE"
