# Publishing a PQVPN Mainnet peer

The public registry is opt-in. Submit a pull request that adds one entry to
`peers.json`. The operator must control the endpoint, accept public discovery,
publish stable hybrid identity fingerprints, state the allowed roles, and
provide an abuse contact. Never commit private keys or passphrases.

Every entry must include:

- `name`: a unique human-readable operator name;
- `endpoint`: a DNS name and UDP port, without credentials;
- `region`: a broad country or regional label;
- `roles`: any of `bootstrap`, `relay`, or `egress`;
- `ed25519_fingerprint` and `ml_dsa_87_fingerprint`;
- `policy_url`, `abuse_contact`, and `consent_recorded_at`.

Egress entries require an explicit acceptable-use policy. A maintainer may
remove an unreachable or unsafe entry without waiting for the operator. Users
must still verify identity fingerprints through an independent channel.
