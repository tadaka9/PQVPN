# Path Quilt blockchain and private navigation

PQVPN means **Path Quilt VPN**. “Post-quantum” describes its hybrid
cryptography; it is not the expansion of the name.

The quilt has two planes. The data plane carries encrypted packets and Asgard
chunks over authenticated peer sessions. The blockchain control plane records
policies, wallet balances, validator-finalized capacity offers and
privacy-bounded service receipts. Browsing destinations, DNS names, URLs, IP
addresses, file names and plaintext never belong in a block or receipt.

## Navigation lifecycle

1. A provider publishes a short-lived hybrid-signed relay or storage offer.
2. Nodes validate its wallet binding, Peer ID, capacity, availability, latency
   bounds, expiry and both signatures.
3. A relay offer may influence only an already authenticated, live session.
4. The client sends traffic in the normal encrypted PQVPN dataplane. Expired or
   silent paths are removed automatically and the original safe scheduler wins.
5. Asgard ranks independent encrypted replicas and verifies each ciphertext
   hash. Failure falls through to the next replica before local decryption.
6. A provider may sign a bucketed service receipt containing offer digest,
   coarse bytes, coarse duration, time and nonce—never the destination.
7. Validators may later admit valid, non-replayed receipts into a bounded
   reward block. A receipt is evidence, not automatic mint authority.

Current production multipath is path selection with liveness failover. A tested
scheduler now provides flow-stable ranking, congestion-window exclusion and a
bounded duplicate-safe reorder buffer. Concurrent striping stays gated until
the authenticated wire sequence format and loss/reordering integration tests
pass. Advertising “bonding” before that would make distant connections less
stable, not faster.

StrangeNet and the 2D world can request a wallet-signed exploration claim. Its
ledger-safe payload contains only achievement class, wallet, timestamp, nonce
and evidence digest. Messages, rooms, coordinates, relationships and participant
IPs are never claim fields; a validator may include or reject it later.

Traffic shaping exposes the same two modes in configuration and GUI: `ai`
trains bounded predictors locally without telemetry; `blockchain` applies
deterministic public bounds and never queries consensus per packet.

## Privacy and abuse boundaries

- capacity never buys validator voting power;
- the ledger cannot reconstruct browsing history;
- offers expire within one hour and cannot select unauthenticated peers;
- storage metrics must remain within configured bounds;
- exact traffic timing and byte counts are reduced to buckets before receipts;
- VPN/StrangeNet transport and storage identities stay separate; an explicit
  social claim is intentionally bound to the self-custody wallet;
- failure to reach consensus stops rewards, never VPN forwarding.

The next engineering gate is authenticated sequence framing and live shard
placement. Until their loss and adversarial tests pass, PQVPN must describe the
feature as latency-aware path selection, tested scheduling/reordering primitives
and replica failover—not simultaneous bonding.
