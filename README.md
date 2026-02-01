# PQVPN

Path Quilt VPN (PQVPN) is a work-in-progress P2P VPN concept project.

## Status

Early-stage scaffolding: repository structure, CI, and documentation are in place. The VPN protocol and networking implementation are not finalized.

## Quick start

Requires Python >=3.10 and <4.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python main.py --help
```

## Repository layout

- `main.py`: primary entrypoint.
- `docs/`: design notes, threat model, roadmap.
- `.github/`: CI, CodeQL, Dependabot.

## Legal

All rights reserved. Copyright (c) 2026 Davide Di Pino.
