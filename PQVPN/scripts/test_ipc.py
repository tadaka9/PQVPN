#!/usr/bin/env python3
"""Small utility to discover and test PQVPN IPC sockets.

Usage examples:
  python3 scripts/test_ipc.py --discover
  python3 scripts/test_ipc.py --socket /run/user/1000/pqvpn_node.sock --ping
  python3 scripts/test_ipc.py --discover --ping
  python3 scripts/test_ipc.py --socket /run/user/1000/pqvpn_node.sock --fix-perms

The --fix-perms option will attempt `pkexec chown user:group socket` then fallback to `sudo chown`.
"""

import argparse
import os
import socket
import json
import subprocess
import sys
from pathlib import Path


def discover_sockets():
    candidates = []
    dirs = []
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        dirs.append(xdg)
    try:
        uid = os.getuid()
        run_user = f"/run/user/{uid}"
        dirs.append(run_user)
    except Exception:
        pass
    dirs.append("/tmp")

    patterns = ["pqvpn*node*.sock", "pqvpn_node*.sock", "pqvpn*.sock"]
    for d in dirs:
        pdir = Path(d)
        if not pdir.exists():
            continue
        for pat in patterns:
            for f in pdir.glob(pat):
                # exclude things that aren't sockets or files we can inspect
                try:
                    if f.is_socket() or f.exists():
                        candidates.append(f)
                except Exception:
                    try:
                        # older Python versions may not have is_socket
                        if f.exists():
                            candidates.append(f)
                    except Exception:
                        pass
    # dedupe preserve order
    seen = set()
    dedup = []
    for p in candidates:
        sp = str(p)
        if sp in seen:
            continue
        seen.add(sp)
        dedup.append(Path(sp))
    return dedup


def show_socket_info(path: Path):
    print(f"Socket: {path}")
    try:
        st = path.stat()
    except Exception as e:
        print("  [!] Cannot stat socket:", e)
        return
    print(f"  owner uid: {st.st_uid}, gid: {st.st_gid}")
    print(f"  mode: {oct(st.st_mode & 0o777)}")
    try:
        import pwd
        import grp

        user = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
        print(f"  owner user: {user}, group: {group}")
    except Exception:
        pass


def try_connect_and_send(path: Path, payload: dict, timeout: float = 1.0):
    print(f"Attempting connect to {path} (timeout={timeout}s)")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(path))
    except Exception as e:
        print("  connect error:", repr(e))
        return None, e
    try:
        data = (json.dumps(payload) + "\n").encode("utf-8")
        s.sendall(data)
    except Exception as e:
        print("  send error:", repr(e))
        try:
            s.close()
        except Exception:
            pass
        return None, e
    # read a line
    try:
        buff = b""
        start = __import__("time").time()
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                chunk = b""
            if not chunk:
                if __import__("time").time() - start > timeout:
                    print("  recv timed out")
                    break
                continue
            buff += chunk
            if b"\n" in buff:
                line, _ = buff.split(b"\n", 1)
                try:
                    raw = line.decode("utf-8", errors="replace")
                    print("  raw response:", raw)
                    try:
                        return json.loads(raw), None
                    except Exception:
                        return raw, None
                except Exception as e:
                    print("  decode error:", e)
                    return None, e
    finally:
        try:
            s.close()
        except Exception:
            pass
    return None, None


def attempt_fix_perms(path: Path) -> bool:
    try:
        import getpass

        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER")
    if not user:
        print("No user detected; cannot chown")
        return False

    pk = ["pkexec", "chown", f"{user}:{user}", str(path)]
    print("Trying pkexec:", " ".join(pk))
    try:
        p = subprocess.Popen(
            pk, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        out, err = p.communicate(timeout=30)
        if out:
            print(out)
        if err:
            print(err)
        if p.returncode == 0:
            print("pkexec chown succeeded")
            return True
    except Exception as e:
        print("pkexec attempt failed:", e)

    su = ["sudo", "chown", f"{user}:{user}", str(path)]
    print("Trying sudo:", " ".join(su))
    try:
        p2 = subprocess.Popen(
            su, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        out2, err2 = p2.communicate(timeout=40)
        if out2:
            print(out2)
        if err2:
            print(err2)
        if p2.returncode == 0:
            print("sudo chown succeeded")
            return True
    except Exception as e:
        print("sudo attempt failed:", e)
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(prog="test_ipc.py")
    ap.add_argument(
        "--discover", action="store_true", help="Discover candidate pqvpn sockets"
    )
    ap.add_argument("--socket", "-s", help="Path to a UNIX socket to test")
    ap.add_argument(
        "--ping", action="store_true", help="Send ping JSON and show response"
    )
    ap.add_argument("--send", help="Send arbitrary JSON payload (string)")
    ap.add_argument(
        "--fix-perms",
        action="store_true",
        help="Attempt to fix perms (pkexec/sudo chown)",
    )
    ap.add_argument(
        "--timeout", type=float, default=1.0, help="Socket connect/read timeout"
    )
    args = ap.parse_args(argv)

    candidates = []
    if args.socket:
        candidates = [Path(args.socket)]
    else:
        candidates = discover_sockets()

    if not candidates:
        print("No candidate sockets found")
        return 2

    for s in candidates:
        print("---")
        show_socket_info(s)
        if args.fix_perms:
            ok = attempt_fix_perms(s)
            print("Fix result:", ok)
        if args.ping or args.send:
            payload = {"cmd": "ping"} if args.ping else None
            if args.send:
                try:
                    payload = json.loads(args.send)
                except Exception:
                    print("Provided --send value is not valid JSON")
                    continue
            resp, err = try_connect_and_send(
                s, payload or {"cmd": "ping"}, timeout=args.timeout
            )
            if err:
                print("Connection/send error:", err)
            else:
                print("Response object:", resp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
