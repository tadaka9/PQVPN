# Architecture (WIP)

PQVPN is in a pre-implementation phase.
This document records the intended components and boundaries so the repo stays coherent as it grows.

## Target components

- Key management (generation, storage, rotation).
- Peer discovery / signaling (mechanism TBD).
- Transport (UDP/TCP/QUIC or equivalent; TBD).
- Handshake and session establishment (post-quantum considerations are part of the research goal).
- Tunnel integration (platform-specific, e.g., TUN/TAP).

## Current state

The current codebase provides a CLI scaffold (`main.py`) and packaging structure (`src/pqvpn/`).
