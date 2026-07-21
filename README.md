# PQVPN

PQVPN is an experimental C++23 migration of the reference implementation in
`main.py`. The command-line node can load and validate a configuration, run a
smoke check, and start its signal-aware runtime loop.

> [!WARNING]
> This project now passes its automated hardening gate, but it has not received
> an independent security audit. Keep new deployments bound to localhost until
> the protocol and implementation have been externally reviewed.

## Build on Ubuntu / WSL

Required system packages include CMake 3.28+, Ninja, a C++23 compiler,
OpenSSL, Argon2, pkg-config, and liboqs. The bundled CMake build downloads
Asio and spdlog during its first configure.

```bash
cd /home/dvx3/Workspace/Projects/PQVPN
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF
cmake --build build --target pqvpn_node
```

The Qt monitor is optional. Enable it with `-DPQVPN_BUILD_MONITOR=ON` and
install the Qt 6 Core, Gui, Widgets, and Network development packages.

## Windows x64 and TAP

The release bundle is produced with MinGW and keeps the C/C++ runtime static.
Install a TAP-Windows6 adapter, then start the bundled `run-pqvpn.cmd` as an
Administrator. The node auto-detects the first TAP adapter; pass
`--tap-guid {GUID}` to select one or `--no-tap` for UDP-only operation.

The current TAP integration manages the device and media state. Automatic
peer selection, Windows route installation, and full bidirectional frame
forwarding remain release blockers before this can be described as a complete
end-user VPN.

## Validate and run

The checked-in `config.json` binds only to `127.0.0.1:9090`.

```bash
./build/pqvpn_node --smoke-test --config config.json
./build/pqvpn_node --config config.json
```

Stop the runtime with Ctrl+C. Use `./build/pqvpn_node --help` for all command
line options.

## Tests and hardening

```bash
cmake -S . -B build-test -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build-test -j2
ctest --test-dir build-test --output-on-failure -j2
```

`pqvpn_hard_kernel` is intentionally strict. A normal build or smoke-test pass
does not imply the security gate passes; treat any future findings as release blockers.
The cryptographic policy is hybrid and fail-closed:

- Authentication: Ed25519 **and** ML-DSA-87 over the same SHA3-512 transcript digest.
- Key establishment: X25519 **and** ML-KEM-1024 combined by HKDF-SHA3-512.
- Session material: role-separated send/receive keys, IV, and session ID derived from the bound transcript.

The current canonical suite contains 60 tests, including loopback UDP dispatch,
X25519 agreement, hybrid authentication, hybrid session installation,
the HKDF-SHA3-512 combiner, ML-DSA-87 round trips, and the hardening gate.
The migration ledger and verified history live in `MIGRATION_MANIFEST.md`,
`MIGRATE.md`, and `UPDATE.md`.
