We present Path-Quilt VPN (PQVPN), a simple, plugin-oriented, and decentralized P2P VPN architecture that departs from traditional centralized VPNs. PQVPN forms ephemeral multi-hop “pathlets” across consenting peers and maintains multiple concurrent end-to-end encrypted circuits to improve resilience and latency. It prioritizes simplicity in configuration and extensibility through a clear plugin interface. The prototype uses ChaCha20-Poly1305 for authenticated encryption and X25519 for key agreement, with Ed25519 identities for signing.

Concept and architecture

    Identity and addressing: Each peer is identified by a long-lived X25519 public key (PeerID). Ed25519 is used to sign identity material. No central controller exists; trust is either TOFU (trust on first use) or configured via allowlists.
    Overlay and routing: Peers participate in a lightweight overlay. Initiators create source-routed, multi-hop pathlets through stateless relays; relays forward sealed frames using only a compact outer header, without keeping per-session state.
    Path agility: Endpoints can maintain 2–4 parallel circuits and switch based on probe measurements, enabling graceful failover and opportunistic performance improvements.
    NAT traversal: Default transport is UDP; other transports (e.g., QUIC/TCP) and rendezvous/discovery methods are pluggable.

Cryptographic protocol (ChaCha20-Poly1305 E2E)

    Handshake: A minimal Noise-inspired handshake derives shared secrets via X25519 and expands them using Argon2 into send/receive keys for ChaCha20-Poly1305 AEAD. Nonces are 96-bit counters per direction. Replay is mitigated by per-circuit sequencing. Rekeying can be triggered periodically or after packet thresholds.
    Data protection: The outer forwarding header is minimal and unencrypted to enable stateless relays; the inner payload is end-to-end encrypted between endpoints using ChaCha20-Poly1305 with associated data binding to essential header fields.

Wire format and control plane

    Outer header: version1, frame_type1, next_hop_peerid_hash8, circuit_id4, length2.
    Frame types: HELLO, HS1/HS2 (handshake), PATH_PROBE/PATH_PONG, RELAY (nested encapsulation), DATA, REKEY, CLOSE, and CONTROL_OPEN (for adapter streams). TLV space supports future extension. Multipath is encoded via distinct circuit_ids.

Configuration and plugins

    Minimal YAML config includes nickname, paths to Ed25519/X25519 keys, bootstrap peers, enabled adapters (SOCKS5 or TUN), and plugin module paths. Plugins implement small interfaces for transport, discovery, routing, adapters, and policy.

Prototype implementation

    The provided single-file Python prototype demonstrates: asyncio UDP transport, stateless relay forwarding, source-routed pathlets, a compact Noise-like handshake with ChaCha20-Poly1305 AEAD, per-direction nonceWe present Path-Quilt VPN (PQVPN), a simple, plugin-oriented, and decentralized P2P VPN architecture that departs from traditional centralized VPNs. PQVPN forms ephemeral multi-hop “pathlets” across consenting peers and maintains multiple concurrent end-to-end encrypted circuits to improve resilience and latency. It prioritizes simplicity in configuration and extensibility through a clear plugin interface. The prototype uses ChaCha20-Poly1305 for authenticated encryption and X25519 for key agreement, with Ed25519 identities for signing.

Concept and architecture

    Identity and addressing: Each peer is identified by a long-lived X25519 public key (PeerID). Ed25519 is used to sign identity material. No central controller exists; trust is either TOFU (trust on first use) or configured via allowlists.
    Overlay and routing: Peers participate in a lightweight overlay. Initiators create source-routed, multi-hop pathlets through stateless relays; relays forward sealed frames using only a compact outer header, without keeping per-session state.
    Path agility: Endpoints can maintain 2–4 parallel circuits and switch based on probe measurements, enabling graceful failover and opportunistic performance improvements.
    NAT traversal: Default transport is UDP; other transports (e.g., QUIC/TCP) and rendezvous/discovery methods are pluggable.

Cryptographic protocol (ChaCha20-Poly1305 E2E)

    Handshake: A minimal Noise-inspired handshake derives shared secrets via X25519 and expands them using Argon2 into send/receive keys for ChaCha20-Poly1305 AEAD. Nonces are 96-bit counters per direction. Replay is mitigated by per-circuit sequencing. Rekeying can be triggered periodically or after packet thresholds.
    Data protection: The outer forwarding header is minimal and unencrypted to enable stateless relays; the inner payload is end-to-end encrypted between endpoints using ChaCha20-Poly1305 with associated data binding to essential header fields.

Wire format and control plane

    Outer header: version1, frame_type1, next_hop_peerid_hash8, circuit_id4, length2.
    Frame types: HELLO, HS1/HS2 (handshake), PATH_PROBE/PATH_PONG, RELAY (nested encapsulation), DATA, REKEY, CLOSE, and CONTROL_OPEN (for adapter streams). TLV space supports future extension. Multipath is encoded via distinct circuit_ids.

Configuration and plugins

    Minimal YAML config includes nickname, paths to Ed25519/X25519 keys, bootstrap peers, enabled adapters (SOCKS5 or TUN), and plugin module paths. Plugins implement small interfaces for transport, discovery, routing, adapters, and policy.

Prototype implementation

    The provided single-file Python prototype demonstrates: asyncio UDP transport, stateless relay forwarding, source-routed pathlets, a compact Noise-like handshake with ChaCha20-Poly1305 AEAD, per-direction nonces, simple rekey trigger, YAML config, and a SOCKS5 adapter. It focuses on clarity and extensibility and intentionally avoids resembling existing VPN code structures. Run as: python pqvpn.py --config config.yaml

s, simple rekey trigger, YAML config, and a minimal SOCKS5 adapter. It focuses on clarity and extensibility and intentionally avoids resembling existing VPN code structures. Run as: python pqvpn.py --config config.yaml

