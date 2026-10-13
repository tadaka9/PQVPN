#!/usr/bin/env bash
set -euo pipefail

encoded_terms=(
  Y29kZXg=
  Y29waWxvdA==
  Y2hhdGdwdA==
  b3BlbmFp
  YXJ0aWZpY2lhbCBpbnRlbGxpZ2VuY2U=
)

for encoded in "${encoded_terms[@]}"; do
  term="$(printf '%s' "$encoded" | base64 --decode)"
  test -n "$term"
  if git grep -nI -i -e "$term" -- . ':!*.lock' ':!tools/check-attribution-policy.sh'; then
    echo "Disallowed attribution reference detected." >&2
    exit 1
  fi
done
