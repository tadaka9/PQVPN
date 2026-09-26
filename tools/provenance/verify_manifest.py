#!/usr/bin/env python3
"""
PQVPN Release Provenance Manifest Verifier

Verifies that release artifacts match the provenance manifest, including
checksum validation and optional PGP signature verification.

Usage:
    python3 verify_manifest.py --manifest <manifest.json> [--artifacts <file1> ...]
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def compute_file_hash(filepath, algorithm="sha256"):
    """Compute cryptographic hash of a file."""
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_artifact(artifact_info):
    """Verify a single artifact against its manifest entry."""
    path = Path(artifact_info["path"])
    
    if not path.exists():
        print(f"  FAIL: File not found: {path}")
        return False
    
    # Verify file size
    stat = path.stat()
    if stat.st_size != artifact_info["size_bytes"]:
        print(f"  FAIL: Size mismatch for {path.name}: expected {artifact_info['size_bytes']}, got {stat.st_size}")
        return False
    
    # Verify SHA-256 checksum
    sha256 = compute_file_hash(path, "sha256")
    if sha256 != artifact_info["sha256"]:
        print(f"  FAIL: SHA-256 mismatch for {path.name}")
        print(f"    Expected: {artifact_info['sha256']}")
        print(f"    Got:      {sha256}")
        return False
    
    # Verify SHA-512 checksum
    sha512 = compute_file_hash(path, "sha512")
    if sha512 != artifact_info["sha512"]:
        print(f"  FAIL: SHA-512 mismatch for {path.name}")
        return False
    
    # Verify PGP signature if present
    if "pgp_signature" in artifact_info:
        try:
            sig_path = path.with_suffix(".asc")
            with open(sig_path, "w") as f:
                f.write(artifact_info["pgp_signature"])
            
            result = subprocess.run(
                ["gpg", "--verify", str(sig_path), str(path)],
                capture_output=True, text=True, check=False
            )
            sig_path.unlink()
            
            if result.returncode != 0:
                print(f"  FAIL: PGP signature verification failed for {path.name}")
                return False
        except Exception as e:
            print(f"  WARN: Could not verify PGP signature for {path.name}: {e}")
    
    print(f"  OK: {path.name} verified")
    return True


def main():
    parser = argparse.ArgumentParser(description="Verify PQVPN release provenance manifest")
    parser.add_argument("--manifest", required=True, help="Path to provenance manifest JSON")
    parser.add_argument("--artifacts", nargs="+", help="Specific artifacts to verify (default: all)")
    
    args = parser.parse_args()
    
    # Load manifest
    try:
        with open(args.manifest) as f:
            manifest = json.load(f)
    except Exception as e:
        print(f"Error loading manifest: {e}", file=sys.stderr)
        return 1
    
    print(f"PQVPN Release Provenance Verification")
    print(f"=====================================")
    print(f"Manifest schema version: {manifest.get('schema_version', 'unknown')}")
    print(f"Build timestamp: {manifest['build']['timestamp']}")
    
    git_info = manifest["build"].get("git", {})
    if git_info:
        print(f"Git commit: {git_info.get('commit_sha', 'unknown')}")
        if git_info.get("tag"):
            print(f"Git tag: {git_info['tag']}")
    
    # Determine which artifacts to verify
    artifacts = manifest["artifacts"]
    if args.artifacts:
        artifacts = [a for a in artifacts if a["name"] in args.artifacts]
    
    print(f"\nVerifying {len(artifacts)} artifact(s):")
    
    all_ok = True
    for artifact_info in artifacts:
        if not verify_artifact(artifact_info):
            all_ok = False
    
    print()
    if all_ok:
        print("RESULT: All artifacts verified successfully [OK]")
        return 0
    else:
        print("RESULT: Verification failed [FAIL]")
        return 1


if __name__ == "__main__":
    sys.exit(main())