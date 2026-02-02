#!/bin/bash

# TESTS Phase: Run automated tests

set -e

echo "=== PQVPN TESTS Phase ==="

# Install deps
pip install -e ".[dev]" --quiet

echo "Running Ruff lint and format..."
ruff check . && ruff format --check .

echo "Running Pytest..."
pytest

echo "Tests completed successfully."