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
    targets = json.loads((root / "packaging/release-targets.json").read_text())
    issues = []
    if not targets or len(set(targets)) != len(targets):
        issues.append("release target list is empty or contains duplicates")
    for target in targets:
        if not isinstance(target, str) or not re.fullmatch(r"[a-z0-9_-]+", target):
            issues.append(f"invalid target: {target!r}")
            continue
        driver = root / "packaging/gates" / target
        if not driver.is_file():
            issues.append(f"{target}: native gate implementation is missing")
        elif not os.access(driver, os.X_OK):
            issues.append(f"{target}: native gate is not executable")
        else:
            # The existing provisional gate explicitly declares these false.
            # Detect that known blocker before consuming a self-hosted runner.
            body = driver.read_text()
            for check in REQUIRED_CHECKS:
                if re.search(r'"' + check + r'"\s*:\s*false\b', body):
                    issues.append(f"{target}: gate explicitly leaves {check} unverified")
    version = (root / "PQVPN_VERSION.txt").read_text().strip()
    if tag:
        if tag != "v" + version:
            issues.append(f"tag {tag} does not match repository version v{version}")
        resolved = subprocess.run(
            ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
            cwd=root, text=True, capture_output=True,
        )
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        if resolved.returncode or resolved.stdout.strip() != head:
            issues.append("release tag must exist and point to the checked-out commit")
    return {"ready": not issues, "version": version, "targets": targets, "issues": issues,
            "scope": "source preflight only; native tests, signatures, and attestations remain required"}


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
