# PQVPN

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tadaka9/PQVPN/ci.yml)](https://github.com/tadaka9/PQVPN/actions)
[![codecov](https://codecov.io/gh/tadaka9/PQVPN/branch/main/graph/badge.svg)](https://codecov.io/gh/tadaka9/PQVPN)
[![GitHub Stars](https://img.shields.io/github/stars/tadaka9/PQVPN.svg)](https://github.com/tadaka9/PQVPN/stargazers)

PQVPN (Path Quilt VPN) is a work-in-progress P2P VPN concept project implementing a novel approach to secure, decentralized networking using post-quantum cryptography and traffic analysis resistance.

## Features

- **Post-Quantum Security**: Utilizes quantum-resistant cryptographic primitives
- **P2P Architecture**: Decentralized peer-to-peer connections without central servers
- **Traffic Obfuscation**: Advanced techniques to resist DPI and traffic analysis
- **IoT Support**: Lightweight client for low-power IoT devices with battery optimization
- **Modular Design**: Plugin-based architecture for extensibility
- **Research-Oriented**: Prototype for exploring VPN security paradigms

## Project Status

⚠️ **This is a research prototype**. The VPN protocol, cryptographic design, and networking/tunneling implementation are not finalized and should not be considered production-ready. Use at your own risk for experimental purposes only.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Development](#development)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Installation

### Requirements

- Python >= 3.10 and < 4.0
- pip

### From Source

```bash
git clone https://github.com/tadaka9/PQVPN.git
cd PQVPN
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -U pip
pip install -e .
```

## Quick Start

```bash
# Activate virtual environment
source .venv/bin/activate

# Run the CLI
pqvpn --help

# Check version
pqvpn version

# Run health check
pqvpn doctor

# Start VPN server (example)
pqvpn run --bind 127.0.0.1 --port 51820

# Start IoT client
pqvpn --iot

# Use WireGuard compatibility mode
pqvpn --protocol wireguard --bind 0.0.0.0 --port 51820
```

## Usage

See [docs/usage.md](docs/usage.md) for detailed usage instructions and examples.

## Development

Follow the structured development loop documented in [docs/DEV_LOOP.md](docs/DEV_LOOP.md).

### Run the full development loop:

```bash
./scripts/dev_loop.sh
# or
make dev-loop
```

### Individual phases:

- `make think` - Brainstorm and document ideas
- `make new` - Implement design changes
- `make security-checks` - Run security audits and static analysis
- `make tests` - Execute automated test suite

### Repository Layout

- `main.py`: Main CLI entrypoint
- `src/pqvpn/`: Core package modules
- `tests/`: Test suite
- `docs/`: Documentation and design notes
- `scripts/`: Development and utility scripts

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Development Plan](docs/DEV_PLAN.md)
- [Roadmap](docs/ROADMAP.md)
- [API Documentation](docs/README.md)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

PQVPN is a research/prototype codebase. Do not use it to protect real traffic until the protocol, implementation, and threat model are complete and independently reviewed.

For security issues, please see [SECURITY.md](SECURITY.md).

## License

All rights reserved. Copyright (c) 2026 Davide Di Pino.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
