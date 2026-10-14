#!/usr/bin/env bash
# Native Debian lifecycle: real old->new upgrade, conffiles, CLI/GUI and purge.
# Run ONLY on an isolated disposable Linux CI runner (invokes sudo apt-get).
# Does not prove privileged PQVPN tunnelling, signatures or provenance.
set -euo pipefail
if [[ "${PQVPN_NATIVE_APT_LIFECYCLE:-}" != 1 ]]; then
    echo 'Refusing privileged apt lifecycle outside an explicitly enabled disposable CI job.' >&2
    exit 2
fi
if [[ $# -ne 2 ]]; then echo "Usage: $0 NEW_DEB PUBLIC_VERSION" >&2; exit 2; fi
PACKAGE="$(realpath "$1")"
VERSION="$2"
source packaging/version-functions.sh
CURRENT="$(pqvpn_debian_version "$VERSION")"
ARCH="$(dpkg --print-architecture)"
OLD_TAG=v0.0.5-alpha-10092026-David0
OLD_NAME="pqvpn_0.0.5-alpha-10092026-David0_$ARCH.deb"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/pqvpn-deb-upgrade-XXXXXX")"
TOUCHED=0
cleanup(){
    status=$?
    if [[ "$TOUCHED" == 1 ]]; then
        sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y pqvpn >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
    return "$status"
}
trap cleanup EXIT
if dpkg-query -W -f='${Status}' pqvpn 2>/dev/null | grep -q 'install ok installed'; then
    echo 'Refusing non-fresh host with installed pqvpn' >&2
    exit 1
fi
test "$(dpkg-deb -f "$PACKAGE" Package)" = pqvpn
test "$(dpkg-deb -f "$PACKAGE" Version)" = "$CURRENT"
test "$(dpkg-deb -f "$PACKAGE" Architecture)" = "$ARCH"
URL="https://github.com/tadaka9/PQVPN/releases/download/$OLD_TAG"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$URL/SHA256SUMS" -o "$WORK/SHA256SUMS"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$URL/$OLD_NAME" -o "$WORK/$OLD_NAME"
python3 - "$WORK/$OLD_NAME" "$WORK/SHA256SUMS" <<'PY'
import hashlib
from pathlib import Path
import re
import sys
artifact, manifest = (Path(x) for x in sys.argv[1:])
matches = [parts[0] for line in manifest.read_text(encoding="ascii").splitlines()
           if len(parts := line.split()) == 2
           and parts[1].lstrip("*") == artifact.name]
if len(matches) != 1 or not re.fullmatch(r"[a-fA-F0-9]{64}", matches[0]):
    raise SystemExit("Expected exactly one pinned historical DEB digest")
if hashlib.sha256(artifact.read_bytes()).hexdigest().lower() != matches[0].lower():
    raise SystemExit("Historical DEB checksum does not match SHA256SUMS")
print("Verified pinned historical Debian package checksum")
PY
test "$(dpkg-deb -f "$WORK/$OLD_NAME" Package)" = pqvpn
test "$(dpkg-deb -f "$WORK/$OLD_NAME" Architecture)" = "$ARCH"
OLD_VERSION="$(dpkg-deb -f "$WORK/$OLD_NAME" Version)"
dpkg --compare-versions "$OLD_VERSION" lt "$CURRENT"

sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$WORK/$OLD_NAME"
TOUCHED=1
test "$(dpkg-query -W -f='${Version}' pqvpn)" = "$OLD_VERSION"
test -x /usr/bin/pqvpn_node
test -s /etc/pqvpn/config.json.example
sudo sh -c 'printf "\n" >> /etc/pqvpn/config.json.example'
INITIAL_HASH="$(sha256sum /etc/pqvpn/config.json.example | awk '{print $1}')"

sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    -o Dpkg::Options::="--force-confold" "$PACKAGE"
test "$(dpkg-query -W -f='${Status}' pqvpn)" = 'install ok installed'
test "$(dpkg-query -W -f='${Version}' pqvpn)" = "$CURRENT"
test "$(sha256sum /etc/pqvpn/config.json.example | awk '{print $1}')" = "$INITIAL_HASH"
test "$(/usr/bin/pqvpn_node --version)" = "PQVPN $VERSION"
/usr/bin/pqvpn_node --validate-config --config /etc/pqvpn/config.json.example
if [[ -x /usr/bin/pqvpn_tui ]]; then
    /usr/bin/pqvpn_tui --smoke-test --config /etc/pqvpn/config.json.example
fi
if [[ -x /usr/bin/pqvpn_monitor ]]; then
    env -u LD_LIBRARY_PATH -u DYLD_LIBRARY_PATH -u DYLD_FRAMEWORK_PATH \
        -u QT_PLUGIN_PATH QT_QPA_PLATFORM=offscreen \
        /usr/bin/pqvpn_monitor --smoke-test --verify-installation
fi
sudo env DEBIAN_FRONTEND=noninteractive apt-get remove -y pqvpn
test ! -e /usr/bin/pqvpn_node
sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y pqvpn
TOUCHED=0
test ! -e /etc/pqvpn/config.json.example
echo "Native Debian lifecycle passed: pinned old->new upgrade, conffile retention, runtime, remove and purge ($ARCH)"
