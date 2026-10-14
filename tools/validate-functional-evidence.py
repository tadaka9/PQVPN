#!/usr/bin/env python3
"""Verify the exact functional release evidence and candidate bytes (schema 2).

This checks an output from a *trusted native qualification job*. It does not
execute any candidate or establish that a self-reported functional test ran;
the native gate must actually perform the tests and the publisher must verify
the candidate's GitHub build-provenance attestation for the same commit/run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

CHECKS = (
    "native_runner", "passed", "privileged_tunnel_e2e",
    "bidirectional_traffic", "route_dns_rollback",
    "clean_install_upgrade_remove", "architecture_verified",
    "runtime_dependencies_verified", "platform_signature_verified",
    "provenance_verified",
)
SUFFIXES = {
    "macos": (".pkg", ".dmg", ".tar.gz"),
    "windows-arm64": (".zip", ".msi"),
    "windows-x86_64": (".msi",),
    "linux": (".tar.gz",),
    "appimage": (".AppImage",),
    "deb": (".deb",),
    "rpm": (".rpm",),
    "arch": (".pkg.tar.xz", ".pkg.tar.zst"),
}


class EvidenceError(ValueError):
    pass


def digest(path):
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def regular_file(path, *, max_bytes):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= max_bytes:
        raise EvidenceError(f"Missing, nonregular, empty, or oversized file: {path}")
    return path


def inspect(evidence_dir, candidate_dir, target, commit, version, *, observed_os=None, observed_arch=None):
    if not re.fullmatch(r"[a-z0-9_-]+", target):
        raise EvidenceError("Invalid target")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise EvidenceError("Invalid commit SHA")
    if not version or any(ch in version for ch in "/\\\x00"):
        raise EvidenceError("Invalid version label")
    evidence_dir, candidate_dir = Path(evidence_dir), Path(candidate_dir)
    evidence_path = regular_file(evidence_dir / "evidence.json", max_bytes=65536)
    log_path = regular_file(evidence_dir / "verification.log", max_bytes=16 * 1024 * 1024)
    if candidate_dir.is_symlink() or not candidate_dir.is_dir():
        raise EvidenceError("Missing or linked candidate directory")
    contents = list(candidate_dir.iterdir())
    if len(contents) != 1:
        raise EvidenceError(f"{target}: expected exactly one candidate, got {len(contents)}")
    candidate = regular_file(contents[0], max_bytes=2 * 1024 * 1024 * 1024)
    # CPack DEB/RPM names use the package-manager normalized version, which
    # may not equal the public version string. The evidence binds both the
    # public version and exact candidate name/hash, while the native driver
    # must validate package metadata against the public source version.
    if not candidate.name.lower().startswith(("pqvpn-", "pqvpn_")):
        raise EvidenceError("Candidate lacks a PQVPN package filename")
    kind = next((key for key in SUFFIXES if target == key or
                 target.startswith(key + "-")), None)
    if kind is None or not candidate.name.endswith(SUFFIXES[kind]):
        raise EvidenceError(f"{target}: unsupported candidate extension")
    try:
        obj = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise EvidenceError("Malformed evidence JSON") from exc
    if not isinstance(obj, dict):
        raise EvidenceError("Evidence must be an object")
    expected = {"schema": 2, "target": target, "commit_sha": commit,
                "version": version, "candidate_name": candidate.name,
                "candidate_size": candidate.stat().st_size,
                "candidate_sha256": digest(candidate),
                "verification_log_sha256": digest(log_path)}
    for key, value in expected.items():
        if obj.get(key) != value:
            raise EvidenceError(f"{target}: missing or incorrect evidence field: {key}")
    for check in CHECKS:
        if obj.get(check) is not True:
            raise EvidenceError(f"{target}: mandatory check not verified: {check}")
    os_name = ("Windows" if target.startswith("windows-") else
               "macOS" if target.startswith("macos-") else "Linux")
    arch = "ARM64" if target.endswith("arm64") else "X64"
    if obj.get("runner_os") != os_name or obj.get("runner_arch") != arch:
        raise EvidenceError(f"{target}: runner OS/CPU mismatch")
    # During native execution, bind the self-reported runner metadata to
    # independently supplied GitHub runner context.
    if observed_os is not None and observed_os != os_name:
        raise EvidenceError(f"{target}: actual runner OS mismatch")
    if observed_arch is not None and observed_arch != arch:
        raise EvidenceError(f"{target}: actual runner CPU mismatch")
    return {"target": target, "sha256": expected["candidate_sha256"],
            "commit": commit, "verified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--candidate-dir", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--runner-os")
    parser.add_argument("--runner-arch")
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.evidence_dir, args.candidate_dir,
                                 args.target, args.commit, args.version,
                                 observed_os=args.runner_os,
                                 observed_arch=args.runner_arch)))
    except (EvidenceError, OSError) as error:
        print(f"Qualification evidence REJECTED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
