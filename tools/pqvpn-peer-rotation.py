#!/usr/bin/env python3
"""Generate a fail-closed PQVPN client profile from a trusted node pool.

The selector rotates only among nodes explicitly marked as egress-capable.
Bootstrap order rotates independently, so a discovery node is never silently
promoted to an exit. Health commands are local operator configuration and are
executed without a shell.
"""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def probe(node: dict, timeout: float) -> dict:
    command = node.get("health_command", [])
    if isinstance(command, str):
        command = shlex.split(command)
    if not command or not all(isinstance(part, str) and part for part in command):
        return {"healthy": False, "latency_ms": None}
    started = time.monotonic()
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
        return {"healthy": result.returncode == 0,
                "latency_ms": round((time.monotonic() - started) * 1000, 1)}
    except (OSError, subprocess.TimeoutExpired):
        return {"healthy": False, "latency_ms": None}


def validate_node(node: dict) -> None:
    required = ("name", "host", "port", "roles", "health_command")
    if any(key not in node for key in required):
        raise ValueError(f"node is missing required fields: {node!r}")
    ipaddress.ip_address(node["host"])
    if not isinstance(node["port"], int) or not 1 <= node["port"] <= 65535:
        raise ValueError(f"{node['name']}: invalid port")
    if not isinstance(node["roles"], list):
        raise ValueError(f"{node['name']}: roles must be an array")
    weight = node.get("capacity_weight", 1.0)
    if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not 0.1 <= weight <= 100:
        raise ValueError(f"{node['name']}: capacity_weight must be between 0.1 and 100")


def rotate(items: list[dict], cursor: int) -> list[dict]:
    if not items:
        return []
    offset = cursor % len(items)
    return items[offset:] + items[:offset]


def select_weighted_exit(exits: list[dict], state: dict, probes: dict) -> tuple[dict, dict]:
    """Allocate new sessions fairly; never stripe packets across exits."""
    previous = state.get("selection_counts", {})
    counts = {node["name"]: max(0, int(previous.get(node["name"], 0))) for node in exits}
    selected = min(exits, key=lambda node: (
        counts[node["name"]] / float(node.get("capacity_weight", 1.0)),
        probes[node["name"]]["latency_ms"] if probes[node["name"]]["latency_ms"] is not None else float("inf"),
        node["name"]))
    counts[selected["name"]] += 1
    if min(counts.values(), default=0) > 1_000_000:
        floor = min(counts.values())
        counts = {name: value - floor for name, value in counts.items()}
    return selected, counts


def write_atomic(path: Path, value: dict, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build_profile(topology: dict, base: dict, state: dict, timeout: float) -> tuple[dict, dict]:
    nodes = topology.get("nodes", [])
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("topology.nodes must contain at least one node")
    for node in nodes:
        validate_node(node)

    probes = {node["name"]: probe(node, timeout) for node in nodes}
    status = {name: result["healthy"] for name, result in probes.items()}
    usable = [node for node in nodes if status[node["name"]] and node.get("enabled", True)]
    exits = [node for node in usable if "exit" in node["roles"]]
    if not exits:
        raise RuntimeError("no healthy declared exit; refusing to generate an unprotected profile")

    cursor = int(state.get("cursor", -1)) + 1
    selected, selection_counts = select_weighted_exit(exits, state, probes)
    discovery = [node for node in usable if {"bootstrap", "relay"} & set(node["roles"])]
    discovery = rotate(discovery, cursor)
    if not discovery:
        raise RuntimeError("no healthy bootstrap or relay peer")

    profile = json.loads(json.dumps(base))
    profile["bootstrap"] = [{"host": node["host"], "port": node["port"]}
                            for node in discovery]
    tunnel = profile.setdefault("tunnel", {})
    tunnel.update({"enabled": True, "exit_host": selected["host"],
                   "exit_port": selected["port"]})
    next_state = {"cursor": cursor, "selected_exit": selected["name"],
                  "health": status, "probes": probes,
                  "selection_counts": selection_counts}
    return profile, next_state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout must be between 0 and 30 seconds")
    lock_path = args.state.with_suffix(args.state.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        topology = load_json(args.topology)
        base = load_json(args.base)
        state = load_json(args.state) if args.state.exists() else {}
        profile, next_state = build_profile(topology, base, state, args.timeout)
        if args.dry_run:
            print(json.dumps({"profile": profile, "state": next_state}, indent=2))
            return 0
        write_atomic(args.output, profile, 0o600)
        write_atomic(args.state, next_state, 0o600)
        print(f"selected exit: {next_state['selected_exit']}; profile: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
