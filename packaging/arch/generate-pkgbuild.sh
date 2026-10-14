#!/usr/bin/env bash
set -euo pipefail

commit="${1:-$(git rev-parse HEAD)}"
output="${2:-packaging/arch/PKGBUILD}"
source .github/dependencies.env
version="$(tr -d '[:space:]' < PQVPN_VERSION.txt)"

if [[ "$version" =~ ^alpha-([0-9]+)\.([0-9]+)-([0-9]+)-([0-9A-Za-z.-]+)$ ]]; then
  pkgver="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.0.alpha.${BASH_REMATCH[3]}.${BASH_REMATCH[4]}"
elif [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  pkgver="${version//-/.}"
else
  echo "Invalid project version label" >&2
  exit 1
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Expected a full 40-character Git commit" >&2
  exit 1
fi

archive_url="https://github.com/tadaka9/PQVPN/archive/$commit.tar.gz"
archive_sha="$(curl --fail --location --silent --show-error "$archive_url" | sha256sum | awk '{print $1}')"
mkdir -p "$(dirname "$output")"
sed \
  -e "s/@PKGVER@/$pkgver/g" \
  -e "s/@COMMIT@/$commit/g" \
  -e "s/@SHA256@/$archive_sha/g" \
  -e "s/@ARGON2_VERSION@/$ARGON2_VERSION/g" \
  -e "s/@LIBOQS_VERSION@/$LIBOQS_VERSION/g" \
  -e "s/@OPENSSL_VERSION@/$OPENSSL_VERSION/g" \
  -e "s/@QT_VERSION@/$QT_VERSION/g" \
  packaging/arch/PKGBUILD.in > "$output"

echo "Generated $output for PQVPN $version at $commit"
