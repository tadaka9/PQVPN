# PQVPN Beta Testnet

This document describes the beta testnet deployment for PQVPN, featuring 5-10 nodes running in a local mesh network.

## Overview

The beta testnet consists of multiple PQVPN nodes running on localhost with different ports. Nodes bootstrap from each other to form a decentralized peer-to-peer network.

## Features Tested

- **Post-Quantum Security**: Utilizes Kyber1024 + ML-DSA-87 for key exchange and signatures
- **Zero-Trust Architecture**: All connections require mutual authentication
- **Anti-DPI Traffic Obfuscation**: Padding and timing randomization to resist traffic analysis
- **Robustness**: Automatic reconnection, session management, and failover

## Deployment

### Automated Deployment

Use the provided script to deploy the testnet:

```bash
cd testnet
python deploy_testnet.py
```

This script:
- Launches 8 nodes on ports 9000-9007
- Configures each node with bootstrap peers pointing to others
- Runs nodes in background until interrupted

### Manual Deployment

1. Create config files for each node (see config0.yaml as example)
2. Start each node with: `python main.py --config configX.yaml`
3. Nodes will automatically discover and connect via bootstrap peers

## Security Considerations

The beta testnet uses:
- Ephemeral keys (not persisted)
- Strict signature verification disabled for easier testing
- Localhost-only binding for security

## Testing

### Manual Tests

- Verify nodes start without errors
- Check logs for successful handshakes
- Test network connectivity between nodes
- Validate cryptographic operations

### Automated Tests

Run the test suite:

```bash
python -m pytest tests/
```

Note: Some tests may require additional dependencies.

## Known Issues

- Config schema has Pydantic annotation issues (fallback used)
- OQS library not installed (emulation mode used)
- External environment prevents package installation for full testing

## Roadmap

- Deploy on multiple machines for distributed testing
- Add monitoring and metrics collection
- Implement automated performance benchmarks
- Add chaos engineering tests for robustness