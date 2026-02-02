#!/usr/bin/env python3
"""
PQVPN Beta Testnet Deployment Script

Deploys a testnet with 5-10 nodes running on localhost with different ports.
Nodes will bootstrap from each other to form a mesh network.
"""

import subprocess
import time
import signal
import os
import sys
import tempfile
import shutil
import yaml

# Number of nodes
NUM_NODES = 8

# Base port
BASE_PORT = 9000

# Base bind host
BIND_HOST = "127.0.0.1"

# Working directory
WORK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def create_node_config(node_id, port, bootstrap_peers):
    """Create a temporary config for the node."""
    config = {
        "peer": {
            "nickname": f"testnet-node-{node_id}"
        },
        "network": {
            "bind_host": BIND_HOST,
            "listen_port": port
        },
        "security": {
            "strict_sig_verify": False,
            "tofu": True,
            "allowlist": []
        },
        "keys": {
            "persist": False
        },
        "bootstrap": bootstrap_peers
    }
    return config

def main():
    print(f"Deploying PQVPN testnet with {NUM_NODES} nodes...")

    # Create bootstrap peers list (all nodes except self)
    all_peers = []
    for i in range(NUM_NODES):
        port = BASE_PORT + i
        all_peers.append({
            "host": BIND_HOST,
            "port": port
        })

    processes = []
    configs = []

    try:
        for i in range(NUM_NODES):
            port = BASE_PORT + i
            # Bootstrap from previous nodes (circular)
            bootstrap = [p for p in all_peers if p["port"] != port]

            config = create_node_config(i, port, bootstrap)

            # Create temp config file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                yaml.safe_dump(config, f)
                config_file = f.name

            configs.append(config_file)

            # Launch node
            cmd = [
                sys.executable, os.path.join(WORK_DIR, "main.py"),
                "--config", config_file
            ]

            print(f"Starting node {i} on port {port}...")
            proc = subprocess.Popen(
                cmd,
                cwd=WORK_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            processes.append(proc)

        print("All nodes started. Waiting for network to form...")

        # Wait a bit for handshake
        time.sleep(10)

        print("Testnet deployed. Nodes are running in background.")
        print("Press Ctrl+C to stop all nodes.")

        # Keep running
        try:
            while True:
                time.sleep(1)
                # Check if any process died
                for i, proc in enumerate(processes):
                    if proc.poll() is not None:
                        print(f"Node {i} exited with code {proc.returncode}")
        except KeyboardInterrupt:
            print("\nStopping testnet...")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Cleanup
        print("Terminating all nodes...")
        for proc in processes:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass

        # Remove temp configs
        for config_file in configs:
            try:
                os.unlink(config_file)
            except:
                pass

        print("Testnet stopped.")

if __name__ == "__main__":
    main()