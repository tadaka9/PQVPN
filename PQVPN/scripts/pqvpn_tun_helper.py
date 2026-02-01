#!/usr/bin/env python3
"""
Privileged helper to create/configure a TUN device for PQVPN.
Designed to be invoked via pkexec or sudo by the GUI.

Usage (examples):
  pkexec /usr/bin/python3 scripts/pqvpn_tun_helper.py --device pqvpn0 --cidr 10.10.10.2/24 --apply-routes
  sudo python3 scripts/pqvpn_tun_helper.py --device pqvpn0 --cidr 10.10.10.2/24 --route-via 192.0.2.1

The helper prints each command before executing it and returns non-zero on failure.
It supports --dry-run to only print the commands.
"""

import argparse
import subprocess
import shlex
import sys


def run(cmd, dry_run=False):
    print(f"> {cmd}")
    sys.stdout.flush()
    if dry_run:
        return 0, ""
    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        print(p.stdout or "", end="")
        return p.returncode, p.stdout
    except Exception as e:
        print(f"Error running command: {e}")
        return 1, str(e)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", "-d", default="pqvpn0")
    parser.add_argument("--cidr", "-c", default="")
    parser.add_argument("--route-via", "-r", default="")
    parser.add_argument("--up-cmd", default="")
    parser.add_argument("--apply-routes", action="store_true")
    parser.add_argument(
        "--force-replace-default",
        action="store_true",
        help="If set, replace the default route via the TUN even without --route-via",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    device = args.device
    cidr = args.cidr
    route_via = args.route_via
    up_cmd = args.up_cmd
    apply_routes = args.apply_routes
    force_replace = args.force_replace_default
    dry_run = args.dry_run

    # Build a list of shell commands (idempotent where possible)
    cmds = []
    cmds.append(f"ip tuntap add dev {shlex.quote(device)} mode tun 2>/dev/null || true")
    if up_cmd:
        cmds.append(up_cmd)
    else:
        if cidr:
            # try add, fall back to replace
            cmds.append(
                f"ip addr add {shlex.quote(cidr)} dev {shlex.quote(device)} 2>/dev/null || ip addr replace {shlex.quote(cidr)} dev {shlex.quote(device)} || true"
            )
        cmds.append(f"ip link set dev {shlex.quote(device)} up 2>/dev/null || true")

    if apply_routes:
        if route_via:
            cmds.append(
                f"ip route replace default via {shlex.quote(route_via)} dev {shlex.quote(device)} || true"
            )
        else:
            if force_replace:
                cmds.append(
                    f"ip route replace default dev {shlex.quote(device)} || true"
                )
            else:
                print(
                    "Skipping replacing default route because --route-via not provided. Use --force-replace-default to force this behavior."
                )

    # Execute
    rc_total = 0
    for c in cmds:
        rc, out = run(c, dry_run=dry_run)
        if rc != 0:
            rc_total = rc_total or rc
    # Print summary
    if dry_run:
        print("\nDry-run complete. No changes applied.")
    else:
        print("\nTUN helper finished. Check interface and routes with `ip` commands.")
    sys.exit(rc_total)


if __name__ == "__main__":
    main()
