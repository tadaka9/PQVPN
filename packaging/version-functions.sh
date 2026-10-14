#!/usr/bin/env bash

pqvpn_debian_version() {
  local version="$1"
  if [[ "$version" =~ ^alpha-([0-9]+)\.([0-9]+)-([0-9]+)-([0-9A-Za-z.-]+)$ ]]; then
    printf '%s.%s.0~alpha-%s-%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
      "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"
  elif [[ "$version" =~ ^([0-9]+)\.([0-9]+)-(alpha|beta)-([0-9]+)-([0-9A-Za-z.-]+)$ ]]; then
    printf '%s.%s.0~%s-%s-%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
      "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}" "${BASH_REMATCH[5]}"
  else
    printf '%s\n' "$version"
  fi
}

pqvpn_arch_version() {
  local version="$1" converted
  if [[ "$version" =~ ^alpha-([0-9]+)\.([0-9]+)-([0-9]+)-([0-9A-Za-z.-]+)$ ]]; then
    converted="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.0.alpha.${BASH_REMATCH[3]}.${BASH_REMATCH[4]}"
  elif [[ "$version" =~ ^([0-9]+)\.([0-9]+)-(alpha|beta)-([0-9]+)-([0-9A-Za-z.-]+)$ ]]; then
    converted="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.0.${BASH_REMATCH[3]}.${BASH_REMATCH[4]}.${BASH_REMATCH[5]}"
  elif [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    converted="$version"
  else
    return 1
  fi
  printf '%s\n' "${converted//-/.}"
}
