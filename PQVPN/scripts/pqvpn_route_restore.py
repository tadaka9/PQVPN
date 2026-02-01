#!/usr/bin/env python3
"""Restore routes helper for PQVPN
Reads a snapshot file containing shell commands (one per line) and executes them as root.
This script is intended to be invoked via pkexec/sudo by the GUI.

The GUI currently snapshots raw output from `ip route show` and `ip rule show`.
This helper accepts both full commands starting with 'ip ' and raw lines like:
  default via 192.0.2.1 dev eth0
or
  0:      from all lookup local
and converts them to executable `ip ...` commands.
"""

import argparse
import subprocess
import sys
import re
from pathlib import Path


def _line_to_cmd(line: str) -> str | None:
    """Convert a snapshot line into an `ip` command or return None to skip."""
    s = line.strip()
    if not s:
        return None
    # If the line already starts with 'ip ', accept it
    if s.startswith("ip "):
        return s
    # if it's a default route line (as produced by `ip route show`), prefix with ip route replace
    if s.startswith("default"):
        return "ip route replace " + s
    # ip rule show output can be like '0:      from all lookup local' or '32766:  from all lookup main'
    m = re.match(r"^(\d+):\s*(.*)", s)
    if m:
        rest = m.group(2).strip()
        # for rule lines, use 'ip rule add <rest>' but remove trailing table numbers if present
        return "ip rule add " + rest
    # fallback: if line contains keywords typical of ip rule
    if any(k in s for k in ("from", "lookup", "pref", "priority", "fwmark")):
        return "ip rule add " + s
    # otherwise skip - unknown format
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--snapshot",
        "-s",
        default="/tmp/pqvpn_prev_routes.txt",
        help="Snapshot file to restore",
    )
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    snap = Path(args.snapshot)
    if not snap.exists():
        print(f"Snapshot file not found: {snap}", file=sys.stderr)
        return 2

    raw_lines = [
        l.rstrip("\n")
        for l in snap.read_text(errors="replace").splitlines()
        if l.strip()
    ]
    if not raw_lines:
        print("Snapshot is empty", file=sys.stderr)
        return 1

    cmds = []
    for ln in raw_lines:
        cmd = _line_to_cmd(ln)
        if cmd:
            cmds.append(cmd)
        else:
            print(f"Skipping unknown snapshot line: {ln}")

    if not cmds:
        print("No executable commands derived from snapshot", file=sys.stderr)
        return 1

    print(f"Restoring routes from: {snap} (commands: {len(cmds)})")
    for cmd in cmds:
        print(f"RUN: {cmd}")
        if args.dry_run:
            continue
        try:
            # Execute the command via shell to support complex constructs; caller (pkexec) provides root
            rc = subprocess.run(cmd, shell=True)
            if rc.returncode != 0:
                print(f"Command failed: {cmd} (rc={rc.returncode})", file=sys.stderr)
        except Exception as e:
            print(f"Exception running: {cmd} -> {e}", file=sys.stderr)
    print("Restore complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
