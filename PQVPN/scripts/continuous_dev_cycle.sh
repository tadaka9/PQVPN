#!/usr/bin/env bash
# Continuous dev cycle: run quick checks and append a short summary to logs/dev_cycle_summary.log
set -e
ROOT="/home/dvx3/Documenti/Programming/Python/PQVPN"
VENV="$ROOT/.venv/bin/python"
LOGDIR="$ROOT/logs"
LOGFILE="$LOGDIR/dev_cycle_summary.log"
mkdir -p "$LOGDIR"
TIMESTAMP=$(date -Iseconds)
(
  echo "[$TIMESTAMP] Dev cycle summary"
  echo "--- healthcheck ---"
  "$VENV" "$ROOT/tools/healthcheck.py" || echo "healthcheck: error"
  echo "--- ruff check (no fixes) ---"
  "$ROOT/.venv/bin/ruff" check "$ROOT" || echo "ruff: issues"
  echo "--- pytest (quick) ---"
  "$ROOT/.venv/bin/pytest" -q -k "handshake or alice" || echo "pytest: failed or no tests"
  echo "---------------------"
) >> "$LOGFILE" 2>&1
