# Threat model (draft)

This document is a starting point and will evolve with the protocol.

## Goals

- Confidentiality and integrity of tunneled traffic.
- Authentication of peers.
- Resistance to passive network observers.

## Non-goals (for now)

- Perfect anonymity.
- Full resistance to endpoint compromise.

## Risks to address

- Key theft (filesystem compromise).
- Downgrade attacks during negotiation.
- Replay and impersonation.
- NAT traversal metadata leakage.
