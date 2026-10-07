#!/usr/bin/env python3
"""
PQVPN Release Provenance Manifest Generator

Generates a JSON manifest containing build metadata, artifact checksums,
and cryptographic signatures for release verification.

Usage:
    python3 generate_manifest.py --artifacts <file1> <file2> ... \
        [--output manifest.json] [--signing-key key.pem]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def get_git_info():
    """Retrieve Git repository information."""
    info = {}
    
    try:
        # Get commit SHA
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True
        )
        info["commit_sha"] = result.stdout.strip()
        
        # Get branch name
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True
        )
        info["branch"] = result.stdout.strip()
        
        # Get tag if on a tagged commit
        result = subprocess.run(
            ["git", "describe", "--tags", "--exact-match"],
            capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            info["tag"] = result.stdout.strip()
        
        # Check for dirty working tree
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, check=True
        )
        info["dirty"] = bool(result.stdout.strip())
        
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Warning: Could not retrieve Git info: {e}", file=sys.stderr)
    
    return info


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


def generate_manifest(artifacts, output_path="provenance-manifest.json", signing_key=None):
    """Generate a provenance manifest for the given artifacts."""
    
    # Build metadata
    build_info = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "generator": "pqvpn-provenance-generator/1.0.0",
        "git": get_git_info()
    }
    
    # Artifact information
    artifact_list = []
    for artifact_path in artifacts:
        path = Path(artifact_path)
        if not path.exists():
            print(f"Warning: Artifact not found: {path}", file=sys.stderr)
            continue
        
        stat = path.stat()
        artifact_info = {
            "name": path.name,
            "path": str(path),
            "size_bytes": stat.st_size,
            "sha256": compute_file_hash(path, "sha256"),
            "sha512": compute_file_hash(path, "sha512")
        }
        
        # Add PGP signature if signing key provided
        if signing_key:
            try:
                result = subprocess.run(
                    ["gpg", "--detach-sign", "-a", f"--local-user={signing_key}", str(path)],
                    capture_output=True, text=True, check=True
                )
                artifact_info["pgp_signature"] = result.stdout.strip()
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"Warning: Could not sign {path.name}: {e}", file=sys.stderr)
        
        artifact_list.append(artifact_info)
    
    # Manifest structure
    manifest = {
        "schema_version": "1.0.0",
        "project": "PQVPN",
        "build": build_info,
        "artifacts": artifact_list
    }
    
    # Write manifest to file
    output = Path(output_path)
    with open(output, "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Provenance manifest generated: {output}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Generate PQVPN release provenance manifest")
    parser.add_argument("--artifacts", nargs="+", required=True, help="Paths to release artifacts")
    parser.add_argument("--output", default="provenance-manifest.json", help="Output manifest path")
    parser.add_argument("--signing-key", help="GPG key ID for signing artifacts")
    
    args = parser.parse_args()
    
    generate_manifest(args.artifacts, args.output, args.signing_key)


if __name__ == "__main__":
    main()