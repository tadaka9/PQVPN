#!/usr/bin/env python3
"""Fail-closed source preflight for PQVPN release qualification.

--integrity-only validates the exact version/tag/commit/target manifest and
reports all qualification gaps without prematurely blocking native matrix jobs.
Normal mode additionally requires every native gate driver to be present,
executable and free of explicitly unverified checks. Neither mode attests
runtime performance, signatures, or provenance.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess

EXPECTED_TARGETS = (
    "macos-arm64", "macos-x86_64", "windows-arm64", "windows-x86_64",
    "linux-arm64", "linux-x86_64", "appimage-arm64", "appimage-x86_64",
    "deb-arm64", "deb-x86_64", "rpm-arm64", "rpm-x86_64", "arch-x86_64",
)
REQUIRED_CHECKS = (
    "privileged_tunnel_e2e", "bidirectional_traffic", "route_dns_rollback",
    "clean_install_upgrade_remove", "runtime_dependencies_verified",
    "platform_signature_verified", "provenance_verified",
)
VERSION_PATTERNS = (
    r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}-[0-9A-Za-z.]+-beta(-[0-9A-Za-z.-]+)?",
    r"alpha-[0-9]+\.[0-9]+-[0-9]+-[0-9A-Za-z.-]+",
    r"[0-9]+\.[0-9]+-(alpha|beta)-[0-9]+-[0-9A-Za-z.-]+",
    r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?",
)


def inspect(root, tag=None):
    root = Path(root)
    details = []

    def issue(code, category, message):
        details.append({"code": code, "category": category, "message": message})

    manifest = root / "packaging/release-targets.json"
    try:
        targets = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        targets = []
        issue("manifest_invalid", "integrity", f"cannot read release target manifest: {error}")
    if not isinstance(targets, list):
        issue("manifest_invalid", "integrity", "release target manifest must be an array")
        targets = []
    if (not targets or
            any(not isinstance(t, str) or not re.fullmatch(r"[a-z0-9_-]+", t) for t in targets) or
            len(targets) != len(set(t for t in targets if isinstance(t, str)))):
        issue("manifest_invalid", "integrity",
              "release targets are empty, invalid, or contain duplicates")
    if set(t for t in targets if isinstance(t, str)) != set(EXPECTED_TARGETS):
        issue("manifest_incomplete", "integrity",
              "release manifest must contain all 13 mandatory targets, without additions")
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
            # A source inspection is only a cheap preflight; the native job
            # must still produce independently checked runtime evidence.
            try:
                body = driver.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                issue("gate_unreadable", "qualification",
                      f"{target}: cannot inspect native gate: {error}")
                continue
            for check in REQUIRED_CHECKS:
                if re.search(r'["\x27]' + check + r'["\x27]\s*:\s*(?:false|False)\b', body):
                    issue("gate_unverified", "qualification",
                          f"{target}: gate explicitly leaves {check} unverified")
    version_file = root / "PQVPN_VERSION.txt"
    try:
        version = version_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        version = ""
        issue("version_invalid", "integrity", f"cannot read project version: {error}")
    if not version or not any(re.fullmatch(pattern, version) for pattern in VERSION_PATTERNS):
        issue("version_invalid", "integrity", "invalid project version label")
    new_beta = re.fullmatch(VERSION_PATTERNS[0], version)
    if new_beta:
        raw_date = version.split("-")[1]
        try:
            datetime.strptime(raw_date, "%m%d%Y")
        except ValueError:
            issue("version_invalid", "integrity", "invalid release calendar date")
    if tag:
        if tag != "v" + version:
            issue("tag_version_mismatch", "integrity",
                  f"tag {tag} does not match repository version v{version}")
        try:
            resolved = subprocess.run(
                ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
                cwd=root, text=True, capture_output=True, check=False,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root,
                text=True, capture_output=True, check=False,
            )
            consistent = (resolved.returncode == 0 and head.returncode == 0 and
                          resolved.stdout.strip() == head.stdout.strip())
        except OSError:
            consistent = False
        if not consistent:
            issue("tag_commit_mismatch", "integrity",
                  "release tag must exist and point to the checked-out commit")
    integrity_valid = not any(entry["category"] == "integrity" for entry in details)
    qualification_ready = not any(entry["category"] == "qualification" for entry in details)
    return {
        "ready": integrity_valid and qualification_ready,
        "integrity_valid": integrity_valid,
        "qualification_ready": qualification_ready,
        "version": version,
        "targets": targets,
        "issues": [entry["message"] for entry in details],
        "issue_details": details,
        "scope": "source preflight only; runtime gates, signatures and attestations mandatory",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tag")
    parser.add_argument("--integrity-only", action="store_true")
    args = parser.parse_args()
    report = inspect(args.root, args.tag)
    print(json.dumps(report, indent=2))
    return 0 if (report["integrity_valid"] if args.integrity_only else report["ready"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
