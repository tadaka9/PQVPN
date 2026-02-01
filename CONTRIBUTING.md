# Contributing to PQVPN

Thanks for your interest in PQVPN.
This project is in an early research/scaffolding stage, so contributions that improve clarity, testing, and structure are especially welcome.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

## Running checks

```bash
# Lint/format
ruff check .
ruff format .

# Tests
pytest
```

## Pull requests

- Keep PRs small and focused.
- Include a brief description of the motivation and what changed.
- Add or update tests when behavior changes.

## Reporting security issues

Please do not open public issues for potential security vulnerabilities.
Follow `SECURITY.md` instead.
