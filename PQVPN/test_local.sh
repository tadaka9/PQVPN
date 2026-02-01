#!/bin/bash

# Test script: start two local PQVPN nodes and test SOCKS5

cd /home/dvx3/Documenti/Programming/Python/PQVPN

# Create bob config pointing to alice
cat > config.yaml << 'EOF'
peer:
  nickname: bob-relay
  role: relay

keys:
  ed25519: bob_ed25519.pem
  x25519: bob_x25519.key

network:
  listen_port: 5556
  bind_host: 0.0.0.0
  bootstrap:
    - "alice@localhost:5555"

adapters: []

logging:
  level: info
  file: bob.log
EOF

# Terminal 1: Start Bob (relay node)
echo "Starting Bob node on port 5556..."
gnome-terminal -- bash -c "cd /home/dvx3/Documenti/Programming/Python/PQVPN && .venv/bin/python main.py --config config.yaml; read -p 'Press enter to close'"

# Wait for Bob to start
sleep 2

# Terminal 2: Start Alice (client with SOCKS5)
echo "Starting Alice node on port 5555 with SOCKS5..."
gnome-terminal -- bash -c "cd /home/dvx3/Documenti/Programming/Python/PQVPN && .venv/bin/python main.py --config config.yaml; read -p 'Press enter to close'"

echo "Both nodes started. SOCKS5 available at 127.0.0.1:1080"

