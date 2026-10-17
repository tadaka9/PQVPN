#!/usr/bin/env python3
"""Fail-closed prototype for the Path Quilt Distributed Scientific Method.

This tool coordinates reproducible evidence. It never executes peer-supplied
code, decides scientific truth, mints PQC, or publishes private data.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_TEXT = 4096
MAX_RESULT = 64 * 1024 * 1024


class MethodError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".pq-research-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def checked_text(name, value):
    value = value.strip()
    if not value or len(value.encode()) > MAX_TEXT:
        raise MethodError(f"{name} must contain 1..{MAX_TEXT} UTF-8 bytes")
    return value


def checked_hash(name, value):
    value = value.lower()
    if not HEX64.fullmatch(value):
        raise MethodError(f"{name} must be a lowercase SHA-256 digest")
    return value


def root_path(value):
    root = Path(value).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise MethodError("state root must be a real directory")
    return root


def experiment_dir(root, experiment_id):
    checked_hash("experiment id", experiment_id)
    path = root / "experiments" / experiment_id
    if path.is_symlink():
        raise MethodError("experiment directory cannot be a symlink")
    return path


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise MethodError(f"invalid state file: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def propose(args):
    protocol = Path(args.protocol).resolve()
    if protocol.is_symlink() or not protocol.is_file() or protocol.stat().st_size > MAX_RESULT:
        raise MethodError("protocol must be a regular file no larger than 64 MiB")
    manifest = {
        "schema": "pq-research-experiment-v1",
        "title": checked_text("title", args.title),
        "hypothesis": checked_text("hypothesis", args.hypothesis),
        "protocol_sha256": digest(protocol.read_bytes()),
        "dataset_sha256": checked_hash("dataset hash", args.dataset_hash),
        "metric": checked_text("metric", args.metric),
        "falsification": checked_text("falsification", args.falsification),
        "licence": checked_text("licence", args.licence),
        "privacy": "public-evidence-no-personal-data",
    }
    experiment_id = digest(manifest)
    directory = experiment_dir(args.root, experiment_id)
    target = directory / "manifest.json"
    if target.exists() and read_json(target) != manifest:
        raise MethodError("experiment id collision")
    atomic_json(target, manifest)
    return {"experiment_id": experiment_id, "manifest": manifest, "status": "proposed"}


def plan(args):
    directory = experiment_dir(args.root, args.experiment)
    manifest = read_json(directory / "manifest.json")
    if not 1 <= args.units <= 10000 or not 2 <= args.replicas <= 7:
        raise MethodError("units must be 1..10000 and replicas 2..7")
    plan_value = {"schema": "pq-research-plan-v1", "experiment_id": args.experiment,
                  "manifest_sha256": digest(manifest), "replicas": args.replicas, "units": []}
    for unit in range(args.units):
        unit_id = digest({"experiment": args.experiment, "unit": unit})
        tasks = [digest({"unit_id": unit_id, "replica": replica}) for replica in range(args.replicas)]
        plan_value["units"].append({"index": unit, "unit_id": unit_id, "tasks": tasks})
    plan_value["plan_sha256"] = digest(plan_value)
    atomic_json(directory / "plan.json", plan_value)
    return {"experiment_id": args.experiment, "plan_sha256": plan_value["plan_sha256"],
            "units": args.units, "replicas": args.replicas, "status": "planned"}


def submit(args):
    directory = experiment_dir(args.root, args.experiment)
    plan_value = read_json(directory / "plan.json")
    peer = checked_hash("peer id", args.peer)
    result = Path(args.result).resolve()
    if result.is_symlink() or not result.is_file() or result.stat().st_size > MAX_RESULT:
        raise MethodError("result must be a regular file no larger than 64 MiB")
    match = next(((unit, task) for unit in plan_value["units"] for task in unit["tasks"]
                  if task == args.task), None)
    if not match:
        raise MethodError("task does not belong to this experiment")
    unit, task = match
    evidence_dir = directory / "evidence" / unit["unit_id"]
    evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for receipt_path in evidence_dir.glob("*.json"):
        receipt = read_json(receipt_path)
        if receipt["peer_id"] == peer:
            raise MethodError("a peer may submit only one replica per unit")
        if receipt["task_id"] == task:
            raise MethodError("task already has evidence")
    receipt = {"schema": "pq-research-evidence-v1", "experiment_id": args.experiment,
               "plan_sha256": plan_value["plan_sha256"], "unit_id": unit["unit_id"],
               "task_id": task, "peer_id": peer, "result_sha256": digest(result.read_bytes()),
               "result_size": result.stat().st_size}
    receipt["receipt_sha256"] = digest(receipt)
    atomic_json(evidence_dir / f"{task}.json", receipt)
    return {"status": "evidence-recorded", "receipt": receipt}


def evaluate(args):
    directory = experiment_dir(args.root, args.experiment)
    plan_value = read_json(directory / "plan.json")
    report = {"schema": "pq-research-report-v1", "experiment_id": args.experiment,
              "plan_sha256": plan_value["plan_sha256"], "units": []}
    counts = {"pending": 0, "reproduced": 0, "conflict": 0}
    for unit in plan_value["units"]:
        evidence_dir = directory / "evidence" / unit["unit_id"]
        receipts = [read_json(path) for path in sorted(evidence_dir.glob("*.json"))] if evidence_dir.exists() else []
        buckets = {}
        for receipt in receipts:
            buckets.setdefault(receipt["result_sha256"], []).append(receipt["peer_id"])
        best = max((len(peers) for peers in buckets.values()), default=0)
        if best >= 2:
            status = "reproduced"
        elif len(receipts) >= plan_value["replicas"]:
            status = "conflict"
        else:
            status = "pending"
        counts[status] += 1
        report["units"].append({"unit_id": unit["unit_id"], "status": status,
                                "evidence_count": len(receipts), "independent_peers": len({r['peer_id'] for r in receipts}),
                                "result_support": {key: len(value) for key, value in sorted(buckets.items())}})
    report["summary"] = counts
    report["report_sha256"] = digest(report)
    atomic_json(directory / "report.json", report)
    return report


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--state", default="~/.local/state/pqvpn/research-method")
    commands = value.add_subparsers(dest="command", required=True)
    create = commands.add_parser("propose")
    create.add_argument("--title", required=True); create.add_argument("--hypothesis", required=True)
    create.add_argument("--protocol", required=True); create.add_argument("--dataset-hash", required=True)
    create.add_argument("--metric", required=True); create.add_argument("--falsification", required=True)
    create.add_argument("--licence", required=True)
    distribute = commands.add_parser("plan")
    distribute.add_argument("--experiment", required=True); distribute.add_argument("--units", type=int, required=True)
    distribute.add_argument("--replicas", type=int, default=3)
    evidence = commands.add_parser("submit")
    evidence.add_argument("--experiment", required=True); evidence.add_argument("--task", required=True)
    evidence.add_argument("--peer", required=True); evidence.add_argument("--result", required=True)
    report = commands.add_parser("evaluate"); report.add_argument("--experiment", required=True)
    return value


def main(argv=None):
    args = parser().parse_args(argv); args.root = root_path(args.state)
    operation = {"propose": propose, "plan": plan, "submit": submit, "evaluate": evaluate}[args.command]
    try:
        print(json.dumps(operation(args), sort_keys=True, ensure_ascii=False))
    except (MethodError, OSError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error), "status": "rejected"}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
