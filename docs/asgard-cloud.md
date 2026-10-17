# Asgard Cloud

Asgard Cloud is PQVPN's zero-telemetry distributed-storage foundation. It
encrypts every 4 MiB chunk locally with AES-256-GCM, derives a distinct key per
object and chunk with HKDF-SHA-256, addresses encrypted blobs by SHA-256, and
places replicas with deterministic rendezvous hashing. More healthy storage
peers allow independent chunks to be written concurrently; they do not weaken
encryption or expose plaintext to a peer.

`tools/asgard-cloud.py` currently targets local paths and operator-mounted
remote volumes. It is a functional storage core, not yet a public cloud: PQVPN
wire transport, signed storage capability advertisements, quotas, garbage
collection, erasure coding, repair and adversarial integration testing remain
release gates. Bootstrap and exit roles never imply storage consent.

Example two-root development configuration:

```json
{
  "replicas": 2,
  "nodes": [
    {"name": "asgard-a", "root": "/srv/asgard/a", "enabled": true},
    {"name": "asgard-b", "root": "/srv/asgard/b", "enabled": true}
  ]
}
```

Store and restore:

```bash
tools/asgard-cloud.py --config asgard.json --key asgard.key put file.bin file.asgard.json
tools/asgard-cloud.py --config asgard.json --key asgard.key get file.asgard.json restored.bin
```

The key and manifest are mode `0600`. Losing the key loses access; leaking it
exposes every object encrypted under it. Production must use an OS keystore or
hardware-backed secret, not synchronization of the raw key to storage peers.
The manifest reveals object size, chunk count and placement names; keep it
private. It is validated as hostile input before any chunk path is accessed.

## Gradual scaling policy

Asgard capacity follows observed demand; it does not reserve a large fleet in
advance and does not send usage telemetry to a central service. Each operator
computes aggregate capacity and service health locally, without object names,
peer identities or access history leaving the node.

1. **0–60% sustained capacity:** keep the existing authorized peers and tune
   bounded concurrency only when queue latency rises.
2. **60–75% for seven daily samples:** plan capacity and validate another
   independent failure domain; do not enroll it yet.
3. **75–85% for three daily samples:** invite one explicitly consenting storage
   peer, rebalance encrypted chunks gradually and verify replica health.
4. **Above 85%, disk-full risk or quorum degradation:** stop accepting writes
   before safety margins are consumed; reads and repair take priority.
5. **Below 40% for 30 daily samples:** recommend consolidation only after every
   object has the requested healthy replica count elsewhere.

Scale decisions use hysteresis, rate limits, per-node quotas and the declared
monthly infrastructure budget. They never purchase resources, change VPN node
roles or copy the master key automatically. Replicas on the same filesystem,
host or provider are useful for testing but do not count as independent
failure domains in production.

## Credits and public-benefit ledger gate

Asgard does **not** currently implement a blockchain, token or payment rail.
No client may sell credits or claim an on-chain donation until the following
shared-ledger gates are complete and independently reviewable:

- a specified consensus and finality model with replay, reorganization and
  double-spend tests;
- non-transferable service credits with no investment, yield or price claim;
- idempotent purchase intents and signed receipts binding currency, gross
  amount, fees, refunds and settlement identifier;
- an immutable allocation rule sending 90% of net distributable proceeds to a
  named eligible charity and 10% to the PQVPN project;
- explicit treatment of processor fees, tax, chargebacks and rounding, so
  “90%” cannot hide an undefined denominator;
- published charity identity, jurisdiction, terms, refund policy, accounting
  period and independently reconcilable monthly totals;
- wallet and key custody that is separate from VPN, StrangeNet and storage
  identity keys.

The intended ledger namespace is shared with future Asgard storage receipts so
storage usage and credit settlement cannot silently fork into incompatible
economies. Storage peers do not gain wallet authority merely by hosting chunks,
and the VPN remains usable without credits. Until every gate above is met, the
purchase capability must remain absent or visibly disabled; a roadmap is not a
cash register.
