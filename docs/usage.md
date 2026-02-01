# Usage

PQVPN ships a small CLI wrapper that launches the node runtime implemented in `main.py` (via `main.main_loop(...)`).

## Run

```bash
# From a repo checkout
python -m pqvpn --config config.yaml

# Or if installed as a package
pqvpn --config config.yaml
```

## Common options

```bash
pqvpn --help

# Change logging
pqvpn --config config.yaml --loglevel DEBUG
pqvpn --config config.yaml --logfile pqvpn.log

# Optional
pqvpn --config config.yaml --pidfile pqvpn.pid
pqvpn --config config.yaml --disable-discovery
pqvpn --config config.yaml --enable-relay
```

## Notes

- The CLI entry point is in `src/pqvpn/cli.py` and supports flags (no subcommands yet).
- The core protocol/transport implementation is currently a single large module (`main.py`) and may change as the project is refactored.
