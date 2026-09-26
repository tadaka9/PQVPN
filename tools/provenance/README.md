# PQVPN Release Provenance Tools

These tools generate and verify cryptographic provenance manifests for PQVPN releases, enabling users to verify the authenticity and integrity of downloaded binaries.

## Overview

The provenance system follows these principles:
- **Reproducibility**: Manifests include Git commit SHA and build metadata
- **Integrity**: SHA-256 and SHA-512 checksums for all artifacts
- **Authenticity**: Optional PGP signatures over artifacts
- **Transparency**: All verification data is publicly available

## Tools

### generate_manifest.py

Generates a provenance manifest JSON file for release artifacts.

```bash
# Basic usage
python3 tools/provenance/generate_manifest.py \
    --artifacts pqvpn-node-v1.0.0-linux-x64.tar.gz pqvpn-tunnel-driver.sys \
    --output provenance-manifest.json

# With PGP signing
python3 tools/provenance/generate_manifest.py \
    --artifacts pqvpn-node-v1.0.0-linux-x64.tar.gz \
    --signing-key YOUR_GPG_KEY_ID \
    --output provenance-manifest.json
```

### verify_manifest.py

Verifies that release artifacts match the provenance manifest.

```bash
# Verify all artifacts in manifest
python3 tools/provenance/verify_manifest.py --manifest provenance-manifest.json

# Verify specific artifact
python3 tools/provenance/verify_manifest.py \
    --manifest provenance-manifest.json \
    --artifacts pqvpn-node-v1.0.0-linux-x64.tar.gz
```

## Manifest Structure

The generated manifest JSON contains:

```json
{
  "schema_version": "1.0.0",
  "project": "PQVPN",
  "build": {
    "timestamp": "2026-09-26T12:00:00Z",
    "generator": "pqvpn-provenance-generator/1.0.0",
    "git": {
      "commit_sha": "abc123...",
      "branch": "main",
      "tag": "v1.0.0",
      "dirty": false
    }
  },
  "artifacts": [
    {
      "name": "pqvpn-node-v1.0.0-linux-x64.tar.gz",
      "path": "./pqvpn-node-v1.0.0-linux-x64.tar.gz",
      "size_bytes": 12345678,
      "sha256": "...",
      "sha512": "...",
      "pgp_signature": "..." // optional
    }
  ]
}
```

## CI Integration

The provenance manifest is automatically generated during release builds in the GitHub Actions workflow. The manifest is uploaded as a release artifact alongside the binaries.

## User Verification Guide

To verify a PQVPN release:

1. Download the release artifacts and `provenance-manifest.json` from the GitHub Releases page
2. Run the verification script:
   ```bash
   python3 tools/provenance/verify_manifest.py --manifest provenance-manifest.json
   ```
3. Check that all artifacts show "OK" status
4. Optionally, verify the PGP signatures using your GPG keyring

## Security Considerations

- The manifest itself should be hosted on a tamper-resistant platform (GitHub Releases)
- For maximum security, users should verify the manifest's Git commit SHA matches the expected release tag
- PGP signatures provide additional authenticity guarantees when the signing key is trusted