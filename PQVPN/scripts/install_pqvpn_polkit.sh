#!/usr/bin/env bash
set -euo pipefail

# Installer for PQVPN TUN helper and polkit policy
# Usage: sudo ./scripts/install_pqvpn_polkit.sh

HELPER_SRC="$(pwd)/scripts/pqvpn_tun_helper.py"
HELPER_DST="/usr/lib/pqvpn/pqvpn_tun_helper.py"
POLICY_SRC="$(pwd)/scripts/org.pqvpn.pqvpn_tun.policy"
POLICY_DST="/usr/share/polkit-1/actions/org.pqvpn.pqvpn_tun.policy"

echo "Installing PQVPN TUN helper to ${HELPER_DST}"
mkdir -p /usr/lib/pqvpn
install -m 0755 "$HELPER_SRC" "$HELPER_DST"
chown root:root "$HELPER_DST"

echo "Installing polkit policy to ${POLICY_DST}"
mkdir -p /usr/share/polkit-1/actions
install -m 0644 "$POLICY_SRC" "$POLICY_DST"
chown root:root "$POLICY_DST"

# install route restore helper
RESTORE_SRC="$(pwd)/scripts/pqvpn_route_restore.py"
RESTORE_DST="/usr/lib/pqvpn/pqvpn_route_restore.py"
if [ -f "$RESTORE_SRC" ]; then
  echo "Installing route restore helper to ${RESTORE_DST}"
  install -m 0755 "$RESTORE_SRC" "$RESTORE_DST"
  chown root:root "$RESTORE_DST"
fi

cat <<'INFO'
Installation complete.
You can now allow GUI to run the helper via pkexec without an explicit password (polkit will still pop up a GUI auth dialog).
To test without GUI, run:
  pkexec /usr/bin/python3 /usr/lib/pqvpn/pqvpn_tun_helper.py --device pqvpn0 --cidr 10.10.10.2/24 --apply-routes --dry-run
  pkexec /usr/bin/python3 /usr/lib/pqvpn/pqvpn_route_restore.py --snapshot /tmp/pqvpn_prev_routes.txt --dry-run

If your distribution rejects pkexec usage, try the sudo fallback or adapt the policy.
INFO
