#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(tr -d '[:space:]' < "$root/PQVPN_VERSION.txt")"
manifest="$root/.github/release-participation.env"

test -f "$manifest" || {
  echo "Release participation manifest is required." >&2
  exit 1
}

# Accept one narrowly scoped assignment; never execute the manifest as shell.
line="$(grep -E '^PQVPN_DAVID_PARTICIPATED=[01]$' "$manifest" || true)"
test "$(printf '%s\n' "$line" | grep -c .)" -eq 1 || {
  echo "PQVPN_DAVID_PARTICIPATED must be explicitly 0 or 1." >&2
  exit 1
}
participated="${line#*=}"
expected="David${participated}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}-${expected}-(alpha|beta)(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Version '$version' conflicts with the participation manifest; expected suffix $expected." >&2
  exit 1
fi

echo "Release participation verified: $expected"
