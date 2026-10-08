#!/usr/bin/env bash
set -euo pipefail

commit="${1:-$(git rev-parse HEAD)}"
output="${2:-packaging/arch/PKGBUILD}"
version="$(tr -d '[:space:]' < VERSION)"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION must contain one semantic version such as 0.0.2" >&2
  exit 1
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Expected a full 40-character Git commit" >&2
  exit 1
fi

archive_url="https://github.com/tadaka9/PQVPN/archive/$commit.tar.gz"
archive_sha="$(curl --fail --location --silent --show-error "$archive_url" | sha256sum | awk '{print $1}')"
pkgver="${version//-/.}"

mkdir -p "$(dirname "$output")"
sed \
  -e "s/@PKGVER@/$pkgver/g" \
  -e "s/@COMMIT@/$commit/g" \
  -e "s/@SHA256@/$archive_sha/g" \
  packaging/arch/PKGBUILD.in > "$output"

echo "Generated $output for PQVPN $version at $commit"
