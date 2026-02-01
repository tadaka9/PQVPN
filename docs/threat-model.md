# Threat Model (WIP)

This threat model is incomplete.
It exists to make assumptions explicit early, not to claim security.

## Non-goals (for now)

- Production-grade anonymity.
- Defense against global passive adversaries.
- Formal verification of the entire implementation.

## Assumptions

- The host OS and kernel are not fully compromised.
- Users can securely obtain and verify PQVPN binaries/source.
- Side-channel protections (timing/cache) are not yet addressed.

## Open questions

- Peer identity model and trust bootstrap.
- Key exchange and authentication strategy.
- Transport selection and NAT traversal approach.
