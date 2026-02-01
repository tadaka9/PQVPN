#!/usr/bin/env python3
"""
PQVPN Key Generation Script

Generates classical and post-quantum keys for PQVPN.
"""

import sys
import os
import argparse

# Add current directory to path for imports
sys.path.insert(0, ".")

from main import ensure_keys, ensure_pq_keys, load_config


def main():
    parser = argparse.ArgumentParser(description="Generate PQVPN keys")
    parser.add_argument(
        "--config", "-c", default="config.yaml", help="Config file path"
    )
    parser.add_argument(
        "--force", "-f", action="store_true", help="Overwrite existing keys"
    )
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"Config file {args.config} not found. Creating default config...")
        create_default_config(args.config)

    try:
        cfg = load_config(args.config)
    except Exception as e:
        print(f"Failed to load config: {e}")
        return 1

    print("Generating classical keys (Ed25519 + X25519)...")
    try:
        ed_priv, x_priv = ensure_keys(cfg)
        print("✅ Classical keys generated successfully")
    except Exception as e:
        print(f"❌ Failed to generate classical keys: {e}")
        return 1

    print("Generating post-quantum keys (Kyber1024 + ML-DSA-65)...")
    try:
        kyber_pk, kyber_sk, dilithium_pk, dilithium_sk = ensure_pq_keys(cfg)
        if kyber_pk:
            print("✅ Post-quantum keys generated successfully")
        else:
            print("⚠️ Post-quantum keys not available (liboqs not found)")
    except Exception as e:
        print(f"❌ Failed to generate post-quantum keys: {e}")
        return 1

    print("\nKey generation complete!")
    return 0


def create_default_config(path):
    """Create a minimal default config file"""
    config = {
        "peer": {"nickname": "node1"},
        "keys": {
            "ed25519": "ed25519.key",
            "x25519": "x25519.key",
            "kyber1024": "kyber1024.key",
            "ml_dsa_65": "ml_dsa_65.key",
        },
        "network": {"listen_port": 0, "bootstrap": []},
    }

    import yaml

    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


if __name__ == "__main__":
    sys.exit(main())
