#!/usr/bin/env python3
"""PQVPN Flux: local-only, privacy-preserving fleet status console."""

from __future__ import annotations

import argparse
import concurrent.futures
import curses
import datetime as dt
import subprocess
import time


NODES = (("AEwarness", "bootstrap"), ("Awarness", "relay · exit"))
REMOTE = r'''LC_ALL=C
printf 'service=%s\n' "$(systemctl is-active pqvpn-mainnet.service 2>/dev/null || echo unknown)"
printf 'enabled=%s\n' "$(systemctl is-enabled pqvpn-mainnet.service 2>/dev/null || echo unknown)"
printf 'udp9090=%s\n' "$(ss -H -lun 'sport = :9090' 2>/dev/null | wc -l)"
printf 'sockets=%s\n' "$(ss -H -un 'sport = :9090' 2>/dev/null | wc -l)"
version="$(pqvpn --version 2>/dev/null | head -1)"; [ -n "$version" ] || version=unavailable
printf 'version=%s\n' "$version"
printf 'uptime=%s\n' "$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)"
printf 'load=%s\n' "$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unavailable)"
awk '/MemTotal:/ {t=$2} /MemAvailable:/ {a=$2} /SwapTotal:/ {s=$2} /SwapFree:/ {f=$2} END {printf "ram_total=%d\nram_used=%d\nswap_total=%d\nswap_used=%d\n",t,t-a,s,s-f}' /proc/meminfo
df -Pk / 2>/dev/null | awk 'NR==2 {printf "disk_total=%s\ndisk_used=%s\ndisk_pct=%s\n",$2,$3,$5}'
'''
ALLOWED = {"service", "enabled", "udp9090", "sockets", "version", "uptime",
           "load", "ram_total", "ram_used", "swap_total", "swap_used",
           "disk_total", "disk_used", "disk_pct"}


def fetch(node: tuple[str, str], timeout: float) -> dict:
    alias, role = node
    started = time.monotonic()
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
               "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
               "-o", f"ConnectTimeout={max(1, int(timeout))}", alias, REMOTE]
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, text=True,
                                capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"name": alias, "role": role, "online": False,
                "error": type(error).__name__}
    values: dict[str, object] = {"name": alias, "role": role,
                                "online": result.returncode == 0,
                                "latency": int((time.monotonic() - started) * 1000)}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ALLOWED:
            values[key] = value[:96]
    if result.returncode:
        values["error"] = f"SSH exit {result.returncode}"
    return values


def mib(value: object) -> str:
    try:
        return f"{int(str(value)) / 1024:.0f} MiB"
    except ValueError:
        return "—"


def rows(item: dict) -> list[tuple[str, str]]:
    if not item["online"]:
        return [("Role", item["role"]), ("State", "OFFLINE / UNREACHABLE"),
                ("Detail", str(item.get("error", "health check failed")))]
    try:
        seconds = int(str(item.get("uptime", 0)))
        uptime = f"{seconds // 86400}d {(seconds % 86400) // 3600:02d}h"
    except ValueError:
        uptime = "—"
    return [("Role", item["role"]),
            ("State", f"{item.get('service', 'unknown')} · SSH {item['latency']} ms"),
            ("UDP 9090", f"listeners {item.get('udp9090', '—')} · aggregate sockets {item.get('sockets', '—')}"),
            ("Version", str(item.get("version", "—"))), ("Uptime", uptime),
            ("Load", str(item.get("load", "—"))),
            ("RAM", f"{mib(item.get('ram_used'))} / {mib(item.get('ram_total'))}"),
            ("Swap", f"{mib(item.get('swap_used'))} / {mib(item.get('swap_total'))}"),
            ("Disk /", f"{mib(item.get('disk_used'))} / {mib(item.get('disk_total'))} · {item.get('disk_pct', '—')}")]


def collect(timeout: float) -> list[dict]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(lambda node: fetch(node, timeout), NODES))


def draw(screen, items: list[dict], interval: float) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    screen.addnstr(0, 1, "PQVPN FLUX · LOCAL ZERO-TELEMETRY CONSOLE", width - 2, curses.A_BOLD)
    screen.addnstr(1, 1, f"{dt.datetime.now().astimezone():%Y-%m-%d %H:%M:%S %Z} · refresh {interval:g}s", width - 2)
    row = 3
    for item in items:
        if row >= height - 2:
            break
        marker = "●" if item["online"] and item.get("service") == "active" else "◆"
        screen.addnstr(row, 1, f"{marker} {item['name']}", width - 2, curses.A_BOLD)
        row += 1
        for key, value in rows(item):
            if row >= height - 2:
                break
            screen.addnstr(row, 3, f"{key:<12} {value}", width - 4)
            row += 1
        row += 1
    screen.addnstr(height - 1, 1, "[r] refresh  [q] quit · no peer IP, peer ID, key, log or payload is collected", width - 2)
    screen.refresh()


def run_tui(screen, interval: float, timeout: float) -> None:
    curses.curs_set(0)
    screen.timeout(max(100, int(interval * 1000)))
    items = collect(timeout)
    while True:
        draw(screen, items, interval)
        key = screen.getch()
        if key in (ord("q"), ord("Q")):
            return
        if key in (-1, ord("r"), ord("R")):
            items = collect(timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.interval <= 3600 or not 1 <= args.timeout <= 30:
        parser.error("interval must be 1..3600 and timeout 1..30 seconds")
    items = collect(args.timeout)
    if args.once:
        for item in items:
            print(f"\n[{item['name']}]")
            for key, value in rows(item):
                print(f"{key:<12} {value}")
        return 0
    curses.wrapper(run_tui, args.interval, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
