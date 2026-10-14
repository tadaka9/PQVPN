#!/usr/bin/env python3
"""Report source-level prerequisites; never substitute for native evidence."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

REQUIRED_CHECKS = (
    "privileged_tunnel_e2e", "bidirectional_traffic", "route_dns_rollback",
    "clean_install_upgrade_remove", "runtime_dependencies_verified",
    "platform_signature_verified", "provenance_verified",
)


def inspect(root, tag=None):
    # Keep human-readable messages stable for existing consumers, while
    # classifying every issue. CI may warn only on known gate shortfalls.
    details = []

    def issue(code, category, message):
        details.append({"code": code, "category": category, "message": message})

    targets = json.loads((root / "packaging/release-targets.json").read_text())
    if not isinstance(targets, list):
        issue("manifest_invalid", "integrity", "release target manifest must be an array")
        targets = []
    if not targets or len(targets) != len({t for t in targets if isinstance(t, str)}):
        issue("manifest_invalid", "integrity",
              "release target list is empty or contains duplicates")
    for target in targets:
        if not isinstance(target, str) or not re.fullmatch(r"[a-z0-9_-]+", target):
            issue("manifest_invalid", "integrity", f"invalid target: {target!r}")
            continue
        driver = root / "packaging/gates" / target
        if not driver.is_file():
            issue("gate_missing", "qualification",
                  f"{target}: native gate implementation is missing")
        elif not os.access(driver, os.X_OK):
            issue("gate_not_executable", "qualification",
                  f"{target}: native gate is not executable")
        else:
            # The provisional gate explicitly declares these false.
            body = driver.read_text()
            for check in REQUIRED_CHECKS:
                if re.search(r'"' + check + r'"\s*:\s*false\b', body):
                    issue("gate_unverified", "qualification",
                          f"{target}: gate explicitly leaves {check} unverified")

    version = (root / "PQVPN_VERSION.txt").read_text().strip()
    valid_version = any(re.fullmatch(pattern, version) for pattern in (
        r"alpha-[0-9]+\.[0-9]+-[0-9]+-[0-9A-Za-z.-]+",
        r"[0-9]+\.[0-9]+-(alpha|beta)-[0-9]+-[0-9A-Za-z.-]+",
        r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?",
    ))
    if not valid_version:
        issue("version_invalid", "integrity", "invalid project version label")
    if tag:
        if tag != "v" + version:
            issue("tag_version_mismatch", "integrity",
                  f"tag {tag} does not match repository version v{version}")
        resolved = subprocess.run(
            ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
            cwd=root, text=True, capture_output=True,
        )
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True,
        )
        if resolved.returncode or head.returncode or resolved.stdout.strip() != head.stdout.strip():
            issue("tag_commit_mismatch", "integrity",
                  "release tag must exist and point to the checked-out commit")
    return {
        "ready": not details, "version": version, "targets": targets,
        "issues": [entry["message"] for entry in details],
        "issue_details": details,
        "scope": "source preflight only; native tests, signatures, and attestations remain required",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tag")
    args = parser.parse_args()
    report = inspect(args.root, args.tag)
    print(json.dumps(report, indent=2))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
