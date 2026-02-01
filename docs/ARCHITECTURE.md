# Architecture (draft)

PQVPN aims to be a peer-to-peer VPN concept project.

## High-level components

- Key management (generation, storage, rotation)
- Identity and authentication (peer identity, handshake)
- Transport (how peers talk: UDP/TCP/QUIC; NAT traversal)
- Tunnel interface integration (OS-specific: Linux/macOS/Windows)
- Control plane vs data plane separation

## Current state

Only repository scaffolding exists (entrypoint, docs, CI). The networking and tunnel implementation are TODO.
