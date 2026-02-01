#!/bin/bash
# Test script for PQVPN

cd /home/dvx3/Documenti/Programming/Python/PQVPN

# Kill old processes
pkill -9 -f "python.*main.py" 2>/dev/null
sleep 2

echo "=== Starting PQVPN Test ==="
echo ""

# Start Bob (relay) in background
echo "1. Starting Bob relay node on port 5556..."
python main.py --config config.yaml --daemon > /tmp/pqvpn_bob.log 2>&1 &
BOB_PID=$!
echo "   Bob PID: $BOB_PID"
sleep 2

# Check if Bob started successfully
if ! ps -p $BOB_PID > /dev/null; then
    echo "❌ Bob failed to start!"
    echo "=== Bob Log ==="
    cat /tmp/pqvpn_bob.log
    exit 1
fi

# Start Alice (client with SOCKS5) in background
echo ""
echo "2. Starting Alice client node on port 5555..."
python main.py --config config.yaml --daemon > /tmp/pqvpn_alice.log 2>&1 &
ALICE_PID=$!
echo "   Alice PID: $ALICE_PID"
sleep 3

# Check if Alice started successfully
if ! ps -p $ALICE_PID > /dev/null; then
    echo "❌ Alice failed to start!"
    echo "=== Alice Log ==="
    cat /tmp/pqvpn_alice.log
    kill $BOB_PID
    exit 1
fi

echo ""
echo "✅ Both nodes started successfully!"
echo ""
echo "=== Bob Log (last 10 lines) ==="
tail -10 /tmp/pqvpn_bob.log

echo ""
echo "=== Alice Log (last 10 lines) ==="
tail -10 /tmp/pqvpn_alice.log

echo ""
echo "=== SOCKS5 Proxy Status ==="
netstat -tlnp 2>/dev/null | grep -E ":(1080|5555|5556)" || echo "Checking with lsof..."
lsof -i :1080 -i :5555 -i :5556 2>/dev/null || echo "Ports in use"

echo ""
echo "📡 SOCKS5 Proxy: 127.0.0.1:1080"
echo "🔗 For testing, configure Firefox:"
echo "   1. Preferences → Network → Settings"
echo "   2. Manual proxy configuration"
echo "   3. SOCKS Host: 127.0.0.1, Port: 1080, Select SOCKS v5"
echo ""
echo "📊 Monitor logs in separate terminals:"
echo "   tail -f /tmp/pqvpn_bob.log"
echo "   tail -f /tmp/pqvpn_alice.log"
echo ""
echo "🛑 Stop test:"
echo "   pkill -9 -f 'python.*main.py'"
