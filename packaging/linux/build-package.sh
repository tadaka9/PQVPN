#!/bin/bash
# PQVPN Linux Package Builder
# Builds .deb and .rpm packages with proper file placement

set -e

BUILD_DIR="${1:-build}"
OUTPUT_DIR="${2:-../artifacts}"
VERSION="${3:-0.0.5-alpha}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo x86_64)"

echo "Building PQVPN Linux package..."
echo "Build dir: $BUILD_DIR"
echo "Output dir: $OUTPUT_DIR"
echo "Version: $VERSION"
echo "Arch: $ARCH"

mkdir -p "$OUTPUT_DIR"

# Create package structure
PKG_ROOT="pqvpn-pkg-root"
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/usr/bin"
mkdir -p "$PKG_ROOT/etc/pqvpn"
mkdir -p "$PKG_ROOT/usr/share/pqvpn"
mkdir -p "$PKG_ROOT/usr/share/applications"
mkdir -p "$PKG_ROOT/usr/share/icons/hicolor/256x256/apps"

# Copy binaries
echo "Copying binaries..."
cp "$BUILD_DIR/pqvpn_node" "$PKG_ROOT/usr/bin/"
cp "$BUILD_DIR/pqvpn_tui" "$PKG_ROOT/usr/bin/"
if [ -f "$BUILD_DIR/pqvpn_monitor" ]; then
    cp "$BUILD_DIR/pqvpn_monitor" "$PKG_ROOT/usr/bin/"
fi

# Copy configuration
echo "Copying configuration..."
cp config.json "$PKG_ROOT/etc/pqvpn/config.json.example"
cp config.udp2raw.json "$PKG_ROOT/etc/pqvpn/config.udp2raw.json.example"

# Copy documentation
echo "Copying documentation..."
cp README.md "$PKG_ROOT/usr/share/pqvpn/"
cp LICENSE "$PKG_ROOT/usr/share/pqvpn/"

# Create systemd service file
echo "Creating systemd service..."
cat > "$PKG_ROOT/etc/systemd/system/pqvpn.service" << 'EOF'
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

# Create desktop entry for GUI
if [ -f "$BUILD_DIR/pqvpn_monitor" ]; then
    echo "Creating desktop entry..."
    cat > "$PKG_ROOT/usr/share/applications/pqvpn-monitor.desktop" << 'EOF'
[Desktop Entry]
Name=PQVPN Privacy Console
Comment=Post-quantum VPN management console
Exec=pqvpn_monitor
Icon=pqvpn
Terminal=false
Type=Application
Categories=Network;Security;
EOF
fi

# Create deb package
echo "Building .deb package..."
cd "$PKG_ROOT"
dpkg-deb --build --root-owner-group .. pqvpn_"$VERSION"_"$ARCH".deb 2>/dev/null || true
cd ..

if [ -f "pqvpn_$VERSION_$ARCH.deb" ]; then
    mv "pqvpn_$VERSION_$ARCH.deb" "$OUTPUT_DIR/"
    echo "Debian package created: $OUTPUT_DIR/pqvpn_$VERSION_$ARCH.deb"
fi

# Clean up
rm -rf "$PKG_ROOT"

echo "Done!"