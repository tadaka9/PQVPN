Path Quilt VPN (PQVPN)
======================

Overview
--------
Path Quilt VPN (PQVPN) is a research / production-oriented VPN prototype combining post-quantum and classical cryptography into a mandatory hybrid handshake and a modular, async Python implementation. It provides authenticated, encrypted UDP-based tunnels and supports circuit-style onion routing, relaying, and routing/topology modules. The project uses liboqs (via Python wrapper) for post-quantum KEM and signature algorithms and stable classical primitives (brainpoolP512r1, ed25519).

High-level goals
-----------------
- Mandatory hybrid handshake that combines Kyber KEM + brainpoolP512r1 ephemeral key exchange and Ed25519 + ML-DSA-87 signatures.
- Secure session establishment (S1/S2 flows), replay protection, and AEAD-protected frames.
- Onion routing primitives for building circuits and relays.
- Per-node temporary key store (OS-agnostic temp dir), regenerated each run and removed on shutdown.
- Background session maintenance (keepalives, rekey triggers, health diagnostics).
- Built-in metrics export (Prometheus) and structured logging.
- CLI entrypoint with configuration file, logging, and daemonization options.

Repository layout
-----------------
- `main.py` — Main application entry, node class `PQVPNNode`, handshake handling (S1/S2), session maintenance, transport/protocol glue, CLI.
- `pqsig.py` / `oqs.py` — OQS wrapper helpers used to sign/verify ML-DSA and other OQS signatures (liboqs integration). Note: the project relies on `oqs` Python package provided by liboqs-python.
- `generate_keys.py` / `create_keys.sh` — Utilities for key generation and key file management.
- `compute_peerid.py` — Utilities to derive peer IDs from public keys.
- `config_schema.py` — Configuration schema and validation helpers.
- `metrics_http.py` — Small HTTP exporter for Prometheus metrics when NetworkAnalytics is enabled.
- `node.py` / `pqvpn_kernel.py` — Core logic split helpers (older refactors). `main.py` currently holds the integrated runtime.
- `tests/` — Unit tests, pytest harness and mocks for handshakes, circuits, and routing.
- `scripts/` — Useful helper scripts (tun setup, installers, debug tools).
- `keys/` — Example or cached keys (not required; runtime uses temporary keys by default).
- `known_peers.yaml`, `config.yaml`, `README_QUICKSTART.yaml` — Example config and known peers.

Key features (implemented so far)
---------------------------------
- Hybrid handshake enforcement: the node will refuse handshakes that do not include both the Kyber KEM/brainpoolP512r1 ephemeral key exchange and dual signatures (Ed25519 + ML-DSA-87). Hybrid mode is mandatory; run fails/aborts if not configured.
- ML-DSA-87 support via liboqs-python: the code uses `oqs.oqs.Signature` to generate, sign, and verify ML-DSA-87 signatures and debugging logic that tries canonical verification call signatures when the wrapper/ABI differs across liboqs versions.
- Kyber KEM integration: usage of `oqs.KeyEncapsulation` to encap/decap and derive shared secrets. Key size checks and regeneration logic added with clear logging and hard failure if probing fails.
- Ed25519 & brainpoolP512r1 classical keys: generated and used for identity / ephemeral shares. Peer ID derived primarily from brainpoolP512r1 public key, falling back to ed25519, kyber or hashed nickname.
- Temporary per-run keys directory: keys are generated into an OS-agnostic temporary directory (under /tmp or platform equivalent) and removed on shutdown using `atexit` and signal handlers. This avoids reusing stale keys accidentally.
- Session lifecycle & maintenance: background task that sends structured keepalive heartbeats (JSON) with fields {type, sessionid, timestamp, peerid, uptime}, runs rekey checks via `rekey_manager.perform_rekey`, and reports diagnostics periodically (active session counts/memory).
- Replay protection fix: the replay window pruning logic uses iterative removal of the oldest counters until window size is satisfied. `nonce_recv` initialization validated.
- Datagram handling hardened: incoming datagrams are parsed conservatively (outer header check), and task creation is bounded by an asyncio.Semaphore to reduce DoS exposure; handshake rate-limiting per IP is available in config.
- Signature verification hardened: if public key length or signature length mismatches expected values, the verification rejects instead of silently trimming. When multiple verification calling conventions are possible across liboqs versions, the code tries different call variants and logs details.
- Keepalive/heartbeat payload is structured JSON and replaces the previous opaque payload. Heartbeat fields include type, sessionid, timestamp, peerid, uptime.
- CLI: main/CLI entry restored and extended with options: `--config`, `--log-level`, `--pid-file`, `--daemonize`, `--no-temp-keys`.
- Relay operation: node can be configured as a relay; `config.yaml` field `relay: true` wires the node to accept and forward circuits as described in onion routing code.

Configuration (sample `config.yaml`)
------------------------------------
This project is driven by a YAML config. Below is a comprehensive sample covering the main features (also included in this README):

```yaml
peer:
  nickname: "Alice"
  # Optional explicit identity keys. By default, keys are generated each run into a temp dir.
  brainpoolP512r1_sk_file: null
  ed25519_sk_file: null

security:
  require_hybrid_handshake: true
  strict_sig_verify: false
  tofu: true
  strict_tofu: false
  known_peers_file: known_peers.yaml
  handshake_per_minute_per_ip: 10

network:
  bind_host: 0.0.0.0
  listen_port: 9000
  max_concurrent_datagrams: 200
  udp_recv_buffer_size: 262144

bootstrap:
  peers:
    - "192.168.50.151:9000"

traffic_obfuscation:
  enabled: false
  buckets: [64, 128, 256, 512, 1024]

rekey:
  interval_seconds: 3600
  threshold_seconds: 1800

relay:
  enabled: true
  accept_circuits: true
  exit_policy: allow-all

metrics:
  prometheus: true
  bind_host: 127.0.0.1
  bind_port: 9001

logging:
  file: pqvpn.log
  level: INFO

keys:
  # If null (default) runtime uses a temporary per-run key directory
  runtime_temp_keys: true
  temp_keys_prefix: pqvpn
```

How to run
----------
- Install Python dependencies (preferably inside a venv):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Ensure liboqs (system lib or build) and liboqs-python (oqs package) are installed.
# Example (Ubuntu): follow liboqs instructions or use the auto-installer in oqs wrapper.
```

- Run the node:

```bash
python main.py --config config.yaml --log-level INFO
```

- Run tests:

```bash
pytest -q
```

- Lint & style (ruff / flake8):

```bash
ruff check . --fix
flake8
```

Notes on liboqs and ML-DSA-87
----------------------------
- The project expects `liboqs` and the `oqs` Python package (liboqs-python). Some systems may distribute different ABI variants; the code performs multiple verification call attempts when verifying ML-DSA signatures to handle wrapper differences. Use `oqs.oqs.get_enabled_sig_mechanisms()` to confirm availability of `ML-DSA-87`.
- Example Python snippet (works in runtime) to test ML-DSA-87:

```python
from oqs import oqs
with oqs.oqs.Signature("ML-DSA-87") as sig:
    pk = sig.generate_keypair()
    msg = b"hello"
    s = sig.sign(msg)
    assert sig.verify(msg, s, pk)
```

Notes on importing the `oqs` Python wrapper
-------------------------------------------
Some installations of the `oqs` Python package expose the library object nested under a top-level package attribute. In this project we require the nested variant to avoid runtime AttributeError issues. Use the following pattern consistently in the code and examples:

```python
from oqs import oqs
# Access the liboqs API via oqs.oqs
with oqs.oqs.Signature("ML-DSA-87") as sig:
    public_key = sig.generate_keypair()
    message = b"hello"
    signature = sig.sign(message)
    assert sig.verify(message, signature, public_key)
```

Example: check enabled signature mechanisms using the nested import pattern:

```bash
python -c "from oqs import oqs; print('\n'.join(oqs.oqs.get_enabled_sig_mechanisms()))"
```

Design notes and implementation details
---------------------------------------
- Handshake (S1/S2): S1 contains an encapsulated Kyber ciphertext (from sender) and both signatures. The receiver decaps with its Kyber secret key and derives symmetric keys from Kyber shared secret + brainpoolP512r1 ephemeral shared key. S2 returns the receiver's encaps and its own signatures and confirms establishment. The code enforces that both Ed25519 and ML-DSA signature verifications succeed unless `strict_sig_verify` is disabled, in which case partial verification is logged and can be accepted.

- Replay window: `SessionInfo.replay_window` is a set with fixed capacity. When full, the code removes the minimum (oldest) counters iteratively until under the size cap; this preserves sliding-window semantics.

- Key management: If stored key files exist but their sizes don't match expected values from OQS probing, the code regenerates the keys. If OQS probing fails to reveal lengths, the code fails loudly so the operator can correct their liboqs installation rather than silently truncating keys.

- Datagram processing: `Protocol.datagram_received` validates an outer header (at least 16 bytes) and reads a 2- or 4-byte length field. Tasks for processing are created by awaiting a per-node `datagram_semaphore` to ensure bounded concurrent processing. Handshake attempts per remote IP are tracked with a `collections.deque` per-IP to rate-limit.

- Keepalive / heartbeat: keepalive payloads are JSON objects with fields {"type": "KEEPALIVE", "sessionid": "...", "timestamp": 123456789, "peerid": "...", "uptime": 12345}. The code parses and responds to these heartbeats to maintain liveness.

- Rekeying: A `KeyRotationManager` is used for planned rekeying. `session_maintenance` periodically checks sessions and triggers `rekey_manager.perform_rekey(session)` when thresholds are exceeded.

- Relay & onion routing: Circuit construction and onion frame building/relaying are implemented. The node can be configured as a relay; relays forward onion frames and apply access/exit policies as configured.

Diagnostics, logging and metrics
-------------------------------
- Structured logging with per-message prefixes and correlation IDs for handshakes/sessions is implemented. Logs redact sensitive key material.
- Periodic diagnostic log entries show active session counts and memory usage.
- NetworkAnalytics exports Prometheus metrics; enable `metrics.prometheus` in config to expose HTTP metrics.

Testing & development
---------------------
- Unit tests for handshake flows (`tests/test_handshake_mock.py`) and circuits (`tests/test_circuits.py`) exist. Tests use mock transports and temporary key directories.
- When adding features, include at least one unit test covering positive and negative handshake verification (hybrid success/failure).
- Use `pytest -k handshake` to run just handshake-related tests while iterating.

Troubleshooting
---------------
- ML-DSA verify failures: check enabled signatures via `python -c "from oqs import oqs; print('\n'.join(oqs.oqs.get_enabled_sig_mechanisms()))"`. If `ML-DSA-87` is not present, install or rebuild liboqs with ML-DSA support.
- Key-size mismatches on startup: ensure liboqs version matches the liboqs-python expectations; the code logs expected vs found sizes. If probing fails, fix environment or set explicit key paths in config.
- If you see many dropped handshakes: tune `security.handshake_per_minute_per_ip` and `network.max_concurrent_datagrams`.

Contribution & roadmap
----------------------
Planned improvements and TODOs:
- Harden and test rekeying logic across many concurrent sessions.
- Add a management REST API (FastAPI) for runtime introspection and control (rekey, drop session, fetch logs).
- Implement multi-path routing and path quality metrics.
- Support for HSM or encrypted key storage and key rotation policies.
- Fuzzing the packet parsers and handshake flows.

License & Credits
-----------------
- Project files contain SPDX header where appropriate (see `scripts/`, some C parts for liboqs adapters).
- This repository bundles glue/experimental code for liboqs and is intended for research and development use. Check upstream licenses for liboqs and other dependencies.

Appendix: Quick commands
------------------------
- Run node: `python main.py --config config.yaml`
- Run tests: `pytest -q`
- Lint & auto-fix: `ruff check . --fix` then `flake8`
- View enabled oqs sigs (nested import pattern):

```bash
python -c "from oqs import oqs; print('\n'.join(oqs.oqs.get_enabled_sig_mechanisms()))"
```

If you want, I can also:
- Add a `README_QUICKSTART.md` with a minimal setup for two-node testing on localhost.
- Generate the `config.yaml` file from the in-memory defaults (I can create it in the repo).
- Run `ruff --fix` and `pytest` in your environment and iterate on any real runtime failures.


Contact / Support
-----------------
Open an issue in the repo with logs (enable DEBUG logging) and the output of `python -c "from oqs import oqs; print(oqs.oqs.get_enabled_sig_mechanisms())"` if you hit ML-DSA verification problems.
