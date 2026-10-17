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

Current multipath is path selection with liveness failover. Concurrent striping
is intentionally gated: TCP and QUIC flows need stable flow affinity, congestion
control, packet numbering, reordering limits and duplicate suppression before
multiple paths can safely carry one connection. Advertising “bonding” without
those mechanisms would make distant connections less stable, not faster.

## Privacy and abuse boundaries

- capacity never buys validator voting power;
- the ledger cannot reconstruct browsing history;
- offers expire within one hour and cannot select unauthenticated peers;
- storage metrics must remain within configured bounds;
- exact traffic timing and byte counts are reduced to buckets before receipts;
- wallet, VPN, StrangeNet and storage identities use separate key domains;
- failure to reach consensus stops rewards, never VPN forwarding.

The next engineering gate is flow-stable concurrent multipath plus erasure-coded
Asgard reconstruction under loss. Until its reorder, congestion and adversarial
tests pass, PQVPN must describe the feature as latency-aware path selection and
replica failover.
