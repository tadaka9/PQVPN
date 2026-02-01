#!/bin/bash
# save as genkeys.sh, chmod +x genkeys.sh

for name in alice bob; do
  echo "Generating keys for $name..."

  # Generate X25519 (32 raw bytes)
  openssl genpkey -algorithm x25519 -out ${name}.x25519

  # Generate Ed25519 (PEM)
  openssl genpkey -algorithm ed25519 -out ${name}.ed25519

  echo "✓ ${name}.x25519 (${name}.x25519)"
  echo "✓ ${name}.ed25519 (${name}.ed25519)"
done
