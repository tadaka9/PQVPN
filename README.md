# PQVPN

PQVPN (Path Quilt VPN) is a work-in-progress P2P VPN concept project.

## Project status

This repository currently provides a **scaffold**: a CLI entrypoint, packaging metadata, and documentation.
The VPN protocol, cryptographic design, and networking/tunneling implementation are not finalized and should not be considered production-ready.

## Quick start (from source)

Requirements: Python >=3.10 and <4.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip

# Run the CLI directly
python main.py --help

# Example commands
python main.py version
python main.py doctor
python main.py run --bind 127.0.0.1 --port 51820
```

## Install (editable, for development)

```bash
python -m pip install -e .

# After install you can use the console script:
pqvpn --help
pqvpn version
```

## Repository layout

- `main.py`: full program + CLI entrypoint.
- `src/pqvpn/`: importable package namespace for future modules.
- `docs/`: design notes and project documentation.
- `tests/`: basic smoke tests for the CLI scaffolding.

## Security notice

PQVPN is a research/prototype codebase.
Do not use it to protect real traffic until the protocol, implementation, and threat model are complete and independently reviewed.

## Legal

All rights reserved. Copyright (c) 2026 Davide Di Pino.
