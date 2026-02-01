#!/bin/bash
# Test PQVPN with Firefox SOCKS5

cd /home/dvx3/Documenti/Programming/Python/PQVPN

echo "=== PQVPN Firefox Test Setup ==="
echo ""
echo "This script will:"
echo "1. Start Bob relay node on port 5556"
echo "2. Start Alice client node on port 5555 with SOCKS5 on 1080"
echo "3. Show commands to configure Firefox"
echo ""

# Check if keys exist
if [ ! -f alice_ed25519.pem ] || [ ! -f bob_ed25519.pem ]; then
    echo "ERROR: Key files not found!"
    echo "Expected: alice_ed25519.pem, bob_ed25519.pem"
    exit 1
fi

echo "Starting Bob relay node..."
.venv/bin/python main.py --config config.yaml &
BOB_PID=$!
sleep 2

echo ""
echo "Starting Alice client node..."
.venv/bin/python main.py --config config.yaml &
ALICE_PID=$!
sleep 2

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Firefox Configuration:"
echo "1. Open Firefox Preferences"
echo "2. Network → Settings"
echo "3. Manual proxy configuration"
echo "4. SOCKS Host: 127.0.0.1, Port: 1080, SOCKS v5"
echo "5. ✓ Proxy DNS when using SOCKS v5"
echo ""
echo "Test URLs:"
echo "- https://whatismyipaddress.com"
echo "- https://ipleak.net"
echo ""
echo "Press Ctrl+C to stop both nodes..."

wait

