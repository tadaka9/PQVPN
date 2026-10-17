# Asgard Cloud

Asgard Cloud is PQVPN's zero-telemetry distributed-storage foundation. It
encrypts every 4 MiB chunk locally with AES-256-GCM, derives a distinct key per
object and chunk with HKDF-SHA-256, addresses encrypted blobs by SHA-256, and
places replicas with deterministic rendezvous hashing. More healthy storage
peers allow independent chunks to be written concurrently; they do not weaken
encryption or expose plaintext to a peer.

`tools/asgard-cloud.py` currently targets local paths and operator-mounted
remote volumes. It is a functional storage core, not yet a public cloud: PQVPN
wire transport, garbage collection, erasure coding and adversarial network
testing remain release gates. Bootstrap and exit roles never imply storage
consent.

Retrieval may use optional integer `latency_ms`, `capacity_bps` and
`availability_ppm` fields on each configured node. Values are strictly bounded;
replicas are tried in deterministic utility order and every ciphertext hash is
verified before decryption. A missing, slow or corrupt preferred replica falls
through to the next independent copy. These metrics select a retrieval path;
they never grant consensus votes or expose object contents on-chain.

Example two-root development configuration:

```json
{
  "replicas": 2,
  "nodes": [
    {"name": "asgard-a", "root": "/srv/asgard/a", "failure_domain": "host-a", "enabled": true},
    {"name": "asgard-b", "root": "/srv/asgard/b", "failure_domain": "host-b", "enabled": true}
  ]
}
```

Store and restore:

```bash
tools/asgard-cloud.py --config asgard.json --key asgard.key put file.bin file.asgard.json
tools/asgard-cloud.py --config asgard.json --key asgard.key get file.asgard.json restored.bin
tools/asgard-cloud.py --config asgard.json audit file.asgard.json
tools/asgard-cloud.py --config asgard.json repair file.asgard.json
```

`audit` exits non-zero when any encrypted chunk lacks the requested number of
independent failure domains. `repair` finds a surviving ciphertext whose
SHA-256 commitment matches, copies only that ciphertext to available distinct
domains, and atomically replaces the manifest only after every chunk regains
quorum. A missing root is never recreated: this prevents a disconnected mount
from being mistaken for healthy local storage.

## Paranoid profile

The core is fail-closed by default: at most 128 explicitly enabled peers, 1–8
replicas, a 1 TiB object bound, bounded JSON inputs, a 64 MiB free-space reserve
per root, private key files restricted to mode `0600`, authenticated encryption,
atomic writes and no unbounded write queue. Replicas sharing a failure domain
do not satisfy quorum. Operators can raise `min_free_bytes` per node, but cannot
disable integrity verification or make an unavailable path silently writable.

Storage consent can be represented with a separate Ed25519 identity and a
signed capability valid for at most 24 hours:

```bash
tools/asgard-cloud.py --identity asgard-identity.key capability-issue capability.json \
  --node asgard-a --capacity-bytes 107374182400 --max-object-bytes 1073741824
tools/asgard-cloud.py capability-verify capability.json
tools/asgard-cloud.py --identity asgard-identity.key receipt-append \
  capability.json file.asgard.json receipts.json
tools/asgard-cloud.py receipt-verify receipts.json
```

Receipts contain only commitments, byte count and a signed hash-chain link: no
IP, filesystem path, filename, object identifier or placement list. Trust still
requires out-of-band public-key pinning. The receipt chain is not consensus,
proof of payment or a blockchain and cannot honestly support credits yet.

The key and manifest are mode `0600`. Losing the key loses access; leaking it
exposes every object encrypted under it. Production must use an OS keystore or
hardware-backed secret, not synchronization of the raw key to storage peers.
The manifest reveals object size, chunk count and placement names; keep it
private. It is validated as hostile input before any chunk path is accessed.
Availability requires at least two genuinely independent devices and periodic
audits; replication cannot save a file if every replica and the private key are
lost together.

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
