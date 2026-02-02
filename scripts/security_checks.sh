#!/bin/bash

# SECURITY-CHECKS Phase: Run audits and scans

set -e

echo "=== PQVPN SECURITY-CHECKS Phase ==="

# Install security tools if not present
pip install -e ".[dev]" --quiet

echo "Running Bandit (security linter)..."
bandit -r src/ main.py || echo "Bandit found issues; review above."

echo "Running Safety (vulnerability check)..."
safety check || echo "Safety found vulnerabilities; review above."

echo "Running Ruff security checks..."
ruff check . --select S || echo "Ruff security issues; review above."

echo "Review docs/THREAT_MODEL.md for any updates needed."

echo "Security checks completed. Review outputs above."