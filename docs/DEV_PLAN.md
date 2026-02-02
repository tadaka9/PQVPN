PQVPN - Development Plan (short-term roadmap)

Goal: move PQVPN from scaffold to runnable prototype with clear modular structure,
repeatable builds, and CI to validate the core runtime.

Time horizon: 4-8 weeks (iterative). Adjust estimates to team size and available CI.

Milestones

1) Repo hygiene & reproducible dev env (1-2 days)
   - Add developer scripts (already added: scripts/install_liboqs.sh)
   - Document local dev setup in README / docs/usage.md (venv, tool versions).
   - Add Makefile / helper scripts to run tests, lint, and start a dev node.

2) Modularize main.py (3-6 days)
   - Extract crypto helpers into src/pqvpn/crypto.py (done, initial extraction)
   - Extract config schema into src/pqvpn/config.py
   - Move DHT/discovery into src/pqvpn/discovery.py
   - Move runtime (PQVPNNode) into src/pqvpn/node.py and provide a minimal CLI shim.
   - Ensure top-level main.py acts as an importable thin shim (for tests) and
     that package entrypoint `pqvpn` uses src/pqvpn/cli.py.

3) Tests & CI (3-5 days)
   - Expand unit tests for: CLI, crypto helpers (mock oqs), config validation, basic node lifecycle.
   - Create GitHub Actions workflow: run flake/ruff, pytest in a reproducible venv, and build packaging.
   - Add example config files and a small integration smoke test (bind to loopback only).

4) Packaging and Distribution (2-4 days)
   - Ensure pyproject.toml metadata is complete.
   - Provide editable install instructions and a lightweight pip wheel build target.
   - Publish internal build artifacts on CI (optional).

5) Feature work: discovery & handshake (ongoing)
   - Harden DHT bootstrap and discovery.
   - Implement and test handshake KEM/signature flows between two nodes.
   - Add operational metrics and health endpoints.

6) Security review & audit (as needed)
   - Threat model review (docs/threat-model.md exists) and 3rd-party cryptography audit
   - Make PKI/TLS and hybrid designs explicit in docs.

Deliverables for next 2 weeks (concrete):
- Working CI that runs linter + tests on push
- Decoupled crypto helpers module (done)
- install_liboqs.sh script (done) and README instructions updated
- A minimal integration test that runs node startup in emulation mode on CI

Notes / Risks
- liboqs & Brainpool/x25519 availability depend on platform and cryptography build.
- Avoid running the full network node on CI (use isolated loopback tests or emulation)
- Keep main.py import-safe (don't perform destructive runtime checks during import)

Next actions I can take now (pick one):
- Create a Makefile and README updates to document the new steps
- Add a GH Actions CI skeleton that runs tests in PQVPN/.venv on push
- Continue refactor by extracting config and node modules into src/pqvpn/* (small, iterative)

