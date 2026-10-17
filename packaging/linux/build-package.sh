#!/bin/bash
# PQVPN Linux package builder (DEB)
# Deploys the complete runtime under /usr/lib/pqvpn with launchers under /usr/bin,
# configuration examples under /etc/pqvpn, the systemd unit under
# /usr/lib/systemd/system, and the desktop entry under /usr/share.

set -euo pipefail
umask 022

BUILD_DIR="${1:-build}"
OUTPUT_DIR="${2:-artifacts}"
VERSION="${3:-$(tr -d '[:space:]' < PQVPN_VERSION.txt)}"
# Optional already-deployed CMake install tree, e.g. the native tar staging tree.
DEPLOY_DIR="${4:-}"
BUILD_DIR="$(realpath "$BUILD_DIR")"
OUTPUT_DIR="$(realpath -m "$OUTPUT_DIR")"
source "$(dirname "${BASH_SOURCE[0]}")/../version-functions.sh"
PACKAGE_VERSION="$(pqvpn_debian_version "$VERSION")"
dpkg --validate-version "$PACKAGE_VERSION"
command -v dpkg-shlibdeps >/dev/null

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
    "$PKG_ROOT/usr/lib/sysctl.d" \
    "$PKG_ROOT/usr/share/polkit-1/rules.d" \
    "$PKG_ROOT/usr/share/applications" \
    "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps"

# Keep the GUI beside its deployed Qt libraries, plugins, and qt.conf. Copying
# only the executable selects an incompatible system Qt on clean machines.
PRIVATE_ROOT="$PKG_ROOT/usr/lib/pqvpn"
mkdir -p "$PRIVATE_ROOT"
if [ -n "$DEPLOY_DIR" ]; then
    DEPLOY_DIR="$(realpath "$DEPLOY_DIR")"
    # CMake rewrites install RPATHs, so byte comparison is inappropriate.
    # GNU build IDs survive that rewrite and tie the stage to these binaries.
    for binary in pqvpn_node pqvpn_tui pqvpn_monitor; do
        if [ ! -f "$BUILD_DIR/$binary" ]; then continue; fi
        build_id="$(readelf -n "$BUILD_DIR/$binary" | awk '/Build ID:/ {print $3}')"
        stage_id="$(readelf -n "$DEPLOY_DIR/bin/$binary" | awk '/Build ID:/ {print $3}')"
        test -n "$build_id"
        test "$build_id" = "$stage_id"
    done
    cp -a "$DEPLOY_DIR/." "$PRIVATE_ROOT/"
else
    cmake --install "$BUILD_DIR" --prefix "$PRIVATE_ROOT"
fi
for binary in pqvpn_node pqvpn_tui pqvpn_monitor; do
    if [ -f "$PRIVATE_ROOT/bin/$binary" ]; then
        ln -s "../lib/pqvpn/bin/$binary" "$PKG_ROOT/usr/bin/$binary"
    fi
done
if [ -f "$PRIVATE_ROOT/bin/pqvpn_monitor" ]; then
    test -s "$PRIVATE_ROOT/bin/qt.conf"
    test -s "$PRIVATE_ROOT/lib/libQt6Core.so.6"
    test -s "$PRIVATE_ROOT/plugins/platforms/libqxcb.so"
fi

# Resolve system dependencies from every shipped ELF object. Bundled SONAMEs
# belong to this package, so omit their self-dependencies while still resolving
# their external dependencies through the system shlibs database.
mkdir -p "$PKG_ROOT/debian"
cat > "$PKG_ROOT/debian/control" <<CONTROL
Source: pqvpn
Section: net
Priority: optional
Maintainer: tadaka9 <tadaka9@users.noreply.github.com>

Package: pqvpn
Architecture: any
Description: PQVPN node and consoles
CONTROL
shlibs="$PKG_ROOT/debian/shlibs.local"
: > "$shlibs"
elfs=()
while IFS= read -r -d '' object; do
    if ! file -b "$object" | grep -q '^ELF'; then continue; fi
    elfs+=("-e$object")
    soname="$(objdump -p "$object" | awk '$1 == "SONAME" {print $2}')"
    if [[ "$soname" =~ ^(.+)\.so\.(.+)$ ]]; then
        printf '%s %s pqvpn (= %s)\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$PACKAGE_VERSION" >> "$shlibs"
    fi
done < <(find "$PRIVATE_ROOT" -type f -print0)
test "${#elfs[@]}" -gt 0
dependencies="$(cd "$PKG_ROOT"; dpkg-shlibdeps -O -xpqvpn -l"$PRIVATE_ROOT/lib" "${elfs[@]}")"
DEPENDENCIES="${dependencies#shlibs:Depends=}, iproute2, nftables, policykit-1"
test -n "$DEPENDENCIES"
rm -rf "$PKG_ROOT/debian"

install -m 0644 config.json "$PKG_ROOT/etc/pqvpn/config.json.example"
install -m 0644 config.udp2raw.json "$PKG_ROOT/etc/pqvpn/config.udp2raw.json.example"
install -m 0644 README.md LICENSE "$PKG_ROOT/usr/share/pqvpn/"
install -m 0755 packaging/linux/pqvpn-linux-network "$PKG_ROOT/usr/lib/pqvpn/pqvpn-linux-network"
install -m 0755 packaging/linux/pqvpn-shield-helper "$PKG_ROOT/usr/lib/pqvpn/pqvpn-shield-helper"
install -m 0755 packaging/linux/pqvpn-research-compute "$PKG_ROOT/usr/lib/pqvpn/pqvpn-research-compute"
install -m 0644 packaging/linux/49-pqvpn-network.rules "$PKG_ROOT/usr/share/polkit-1/rules.d/49-pqvpn-network.rules"
install -m 0644 packaging/linux/60-pqvpn-network-performance.conf \
    "$PKG_ROOT/usr/lib/sysctl.d/60-pqvpn-network-performance.conf"

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
    install -m 0644 assets/brand/logo.svg "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps/pqvpn.svg"
    test -s "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps/pqvpn.svg"
fi

# Some desktop environments (including COSMIC) do not refresh their icon and
# application caches merely because dpkg unpacked a new SVG.  Refresh the
# standard caches after install while keeping the package usable on minimal
# servers where the cache helpers are intentionally absent.
cat > "$PKG_ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache --quiet --force /usr/share/icons/hicolor || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database --quiet /usr/share/applications || true
fi
# Apply PQVPN's socket-buffer ceilings immediately. systemd-sysctl commonly
# lives outside PATH on Debian-family hosts; sysctl is a narrow fallback that
# reads only PQVPN's file rather than reloading unrelated administrator policy.
if [ -x /usr/lib/systemd/systemd-sysctl ]; then
    /usr/lib/systemd/systemd-sysctl \
        --prefix=/net/core/rmem_max --prefix=/net/core/wmem_max || true
elif command -v sysctl >/dev/null 2>&1; then
    sysctl -p /usr/lib/sysctl.d/60-pqvpn-network-performance.conf || true
fi
exit 0
EOF
chmod 0755 "$PKG_ROOT/DEBIAN/postinst"

cat > "$PKG_ROOT/DEBIAN/control" << EOF
Package: pqvpn
Version: $PACKAGE_VERSION
Architecture: $ARCH
Maintainer: tadaka9 <tadaka9@users.noreply.github.com>
Depends: $DEPENDENCIES
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

# Configuration examples receive conffile protection so local edits
# survive package upgrades.
printf '/etc/pqvpn/config.json.example\n/etc/pqvpn/config.udp2raw.json.example\n' \
    > "$PKG_ROOT/DEBIAN/conffiles"

dpkg-deb --build --root-owner-group "$PKG_ROOT" "$DEB_FILE"
rm -rf "$PKG_ROOT"
dpkg-deb --info "$DEB_FILE" > /dev/null
echo "Debian package created: $DEB_FILE"
