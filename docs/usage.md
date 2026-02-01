# Usage

PQVPN currently ships a minimal CLI scaffold to make the repository runnable while the core protocol and networking stack are designed.

## Commands

```bash
# Help
pqvpn --help

# Version
pqvpn version

# Basic environment checks
pqvpn doctor

# Placeholder run command
pqvpn run --bind 127.0.0.1 --port 51820
```

## Notes

- `run` is a placeholder and does not create a real tunnel yet.
- The CLI is implemented in `main.py`.
