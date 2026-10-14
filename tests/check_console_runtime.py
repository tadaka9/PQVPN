"""Verify diagnostic secrecy and GUI shutdown with the actual node process."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--node", required=True)
parser.add_argument("--template", required=True)
args = parser.parse_args()
node = str(Path(args.node).resolve())
with tempfile.TemporaryDirectory(prefix="pqvpn-console-runtime-") as directory:
    root = Path(directory)
    config = json.loads(Path(args.template).read_text())
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config["network"] = {"port": port, "bind_address": "127.0.0.1"}
    config["bootstrap"] = []
    config["security"]["known_peers_file"] = str(root / "known_peers.json")
    sentinel = "LOCAL_RUNTIME_TEST_PASSPHRASE"
    config["security"]["known_peers_passphrase"] = sentinel
    profile = root / "config.json"
    profile.write_text(json.dumps(config))
    for flag in ("--print-config", "--smoke-test"):
        result = subprocess.run([node, flag, "--config", str(profile)],
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, "diagnostic command failed"
        assert sentinel not in result.stdout + result.stderr, "diagnostic exposed passphrase"
    with (root / "runtime.log").open("w+") as log:
        process = subprocess.Popen([node, "--no-tunnel", "--control-stdin", "--config", str(profile)],
                                   stdin=subprocess.PIPE, stdout=log, stderr=log, text=True)
        try:
            process.stdin.write('{"command":"node.shutdown"}\n')
            process.stdin.flush()
            # Keep stdin open: shutdown must also release its reader thread.
            assert process.wait(timeout=20) == 0, "clean shutdown failed"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdin.close()
        log.seek(0)
        output = log.read()
        assert "Runtime started" in output and "Runtime stopped" in output, "runtime was not exercised"
        assert sentinel not in output, "runtime exposed passphrase"
    assert (root / "node_keys.json").exists(), "identity was not persisted"
print("Diagnostic secrecy and JSON runtime shutdown passed")
