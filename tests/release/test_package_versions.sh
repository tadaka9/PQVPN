#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../../packaging/version-functions.sh"

alpha="$(pqvpn_debian_version alpha-0.6-10142026-cybergun)"
beta="$(pqvpn_debian_version 0.6-beta-10142026-David0-OTA)"
test "$alpha" = "0.6.0~alpha-10142026-cybergun"
test "$beta" = "0.6.0~beta-10142026-David0-OTA"
dpkg --compare-versions "$alpha" lt "$beta"
dpkg --compare-versions "$beta" lt "0.6.0"

arch="$(pqvpn_arch_version 0.6-beta-10142026-David0-OTA)"
test "$arch" = "0.6.0.beta.10142026.David0.OTA"
[[ "$arch" != *-* ]]

new_beta="$(pqvpn_debian_version 0.0.9-10152026-David0-beta-OTA)"
test "$new_beta" = "0.0.9~beta-10152026-David0-OTA"
new_arch="$(pqvpn_arch_version 0.0.9-10152026-David0-beta-OTA)"
test "$new_arch" = "0.0.9.beta.10152026.David0.OTA"
dpkg --compare-versions "0.0.5" lt "$new_beta"
