#!/usr/bin/env bash
set -euo pipefail
WORKDIR="/home/dvx3/Workspace/PQVPN"
LOGDIR="$WORKDIR/logs/cron"
mkdir -p "$LOGDIR"
TS=$(date --iso-8601=seconds)
OUT="$LOGDIR/summary-$(date +%Y%m%dT%H%M%S).md"
echo "# PQVPN 15m dev summary - $TS" > "$OUT"
cd "$WORKDIR"
echo "## Repository status" >> "$OUT"
echo '\n' >> "$OUT"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo '### Git status (porcelain):' >> "$OUT"
  git status --porcelain >> "$OUT" || true
  echo '\n' >> "$OUT"
  echo '### Latest commit:' >> "$OUT"
  git --no-pager log -1 --pretty=format:'%h %ad %s (%an)' >> "$OUT" || true
else
  echo "Git repo not found in workspace" >> "$OUT"
fi

# Tests
echo "## Tests" >> "$OUT"
if command -v pytest >/dev/null 2>&1; then
  echo "Running pytest (quick, -q)" >> "$OUT"
  pytest -q || echo "pytest returned non-zero" >> "$OUT"
else
  echo "pytest not available in PATH" >> "$OUT"
fi

# Lint
echo "## Lint" >> "$OUT"
if command -v ruff >/dev/null 2>&1; then
  echo "Running ruff check --fix (dry run)" >> "$OUT"
  ruff check . || echo "ruff reported issues" >> "$OUT"
else
  echo "ruff not available in PATH" >> "$OUT"
fi

# Security / OQS
echo "## Security / OQS" >> "$OUT"
# Prefer project venv python if present
if [ -x "$(pwd)/.venv/bin/python" ]; then
  PY="$(pwd)/.venv/bin/python"
else
  PY="$(command -v python || command -v python3 || true)"
fi
if [ -n "$PY" ]; then
  echo "Using $PY to probe oqs" >> "$OUT"
  "$PY" - <<'PY' >> "$OUT" 2>&1 || true
try:
    from oqs import oqs
    print('oqs lib available')
    try:
        print('\nEnabled sig mechanisms:')
        # Normalize access: some wrappers expose oqs.oqs directly
        try:
            print('\n'.join(oqs.oqs.get_enabled_sig_mechanisms()))
        except Exception:
            try:
                print('\n'.join(oqs.get_enabled_sig_mechanisms()))
            except Exception as e:
                print('Error listing sigs:', e)
    except Exception as e:
        print('Error listing sigs:', e)
except Exception as e:
    print('oqs import failed:', e)
PY
else
  echo "Python not found" >> "$OUT"
fi

# Recent logs
echo "## Recent logs (last 200 lines)" >> "$OUT"
LOGFILE="$WORKDIR/logs/pqvpn.log"
if [ -f "$LOGFILE" ]; then
  echo "### pqvpn.log (tail 200)" >> "$OUT"
  tail -n 200 "$LOGFILE" >> "$OUT"
else
  echo "pqvpn.log not found" >> "$OUT"
fi

# Artifacts
echo "## Artifacts & test reports" >> "$OUT"
find . -maxdepth 2 -type f -name "test-report-*.json" -print >> "$OUT" || true

# Done
echo "Summary written to $OUT"
cat "$OUT"
