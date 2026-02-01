#!/bin/bash
# Run PQVPN nodes persistently for Firefox

cd /home/dvx3/Documenti/Programming/Python/PQVPN

# Kill old processes
pkill -9 -f "python.*main.py" 2>/dev/null || true
sleep 1

echo "=== Starting PQVPN Nodes ==="
echo ""

# Start Bob (relay) in background
echo "Starting Bob relay node on port 5556..."
.venv/bin/python main.py --config config.yaml > /tmp/pqvpn_bob.log 2>&1 &
BOB_PID=$!
echo "Bob PID: $BOB_PID"
sleep 2

# Start Alice (client with SOCKS5) in background
echo "Starting Alice client node on port 5555..."
.venv/bin/python main.py --config config.yaml > /tmp/pqvpn_alice.log 2>&1 &
ALICE_PID=$!
echo "Alice PID: $ALICE_PID"
sleep 5

echo ""
echo "=== Status Check ==="
ps aux | grep "main.py" | grep -v grep

echo ""
echo "=== Bob Log (last 10 lines) ==="
tail -10 /tmp/pqvpn_bob.log

echo ""
echo "=== Alice Log (last 10 lines) ==="
tail -10 /tmp/pqvpn_alice.log

echo ""
echo "✅ PQVPN is running!"
echo ""
echo "📡 SOCKS5 Proxy: 127.0.0.1:1080"
echo ""
echo "🔥 Firefox Configuration:"
echo "   1. Open Firefox Preferences"
echo "   2. Network → Settings"
echo "   3. Manual proxy configuration"
echo "   4. SOCKS Host: 127.0.0.1"
echo "   5. Port: 1080"
echo "   6. Select: SOCKS v5"
echo "   7. ✓ Enable 'Proxy DNS when using SOCKS v5'"
echo ""
echo "🌐 Test URLs:"
echo "   - https://www.google.com"
echo "   - https://whatismyipaddress.com"
echo ""
echo "📊 Monitor logs:"
echo "   Bob:   tail -f /tmp/pqvpn_bob.log"
echo "   Alice: tail -f /tmp/pqvpn_alice.log"
echo ""
echo "🛑 Stop nodes:"
echo "   pkill -9 -f 'main.py'"
echo ""
