# PQ Mesh Ledger: the deliberate compromise

Status: design contract for an experimental testnet. Implemented features are
marked separately from proposed work; this document is not an investment paper.

PQVPN should not combine fashionable mechanisms merely because they exist. Its
ledger has three jobs: agree on scarce PQ units, record reproducible useful-work
evidence, and remain operable on a small privacy network. The design therefore
borrows properties, not code or branding, from established protocols.

## Decision matrix

| Source idea | Property retained | What PQVPN deliberately rejects |
|---|---|---|
| [Bitcoin](https://bitcoin.org/bitcoin.pdf) | fixed 21,000,000 cap, explicit genesis, hash-linked history, independently reproducible validation | energy-intensive proof of work and probabilistic settlement |
| [CometBFT](https://docs.cometbft.com/main/spec/consensus/consensus) | deterministic finality after a `floor(2N/3)+1` certificate; a partition without quorum stops | longest-chain recovery and silent reorganization of finalized history |
| [Algorand](https://arxiv.org/abs/1607.01341) | future VRF-based, unpredictable committee rotation to reduce targeted attacks | stake-weighted plutocracy and an unreviewed home-grown VRF |
| [Ethereum PoS](https://ethereum.org/developers/docs/consensus-mechanisms/pos/) | explicit equivocation evidence, validator removal process and recent trusted recovery checkpoints | making token wealth the validator-admission criterion or enabling speculative slashing before governance exists |
| [Filecoin](https://spec.filecoin.io/algorithms/pos/) | challenge-based proof that storage remains available over time | equating raw storage capacity with consensus control |
| [Zcash](https://zips.z.cash/protocol/protocol.pdf) and [Monero Research Lab](https://www.getmonero.org/resources/research-lab/) | future confidential transfers with selective disclosure/view capability | claiming transaction privacy before circuits, supply proofs and audits exist |

## Chosen architecture

### 1. Consensus: identity-bounded BFT

The first network uses a small, published validator set. Every policy, proposal,
vote, attestation and transfer is domain-separated and authenticated with both
Ed25519 and ML-DSA-87. A block becomes final only with a supermajority
certificate. A minority partition halts instead of inventing a competing truth.

This is not permissionless yet. The trade is honest: deterministic finality and
Sybil resistance come from a governed validator registry while the network is
small. Permissionless admission requires a separately reviewed mechanism; PQ
ownership, storage volume and compute power must not buy unilateral consensus.

### 2. Supply: Bitcoin-like scarcity without proof of work

The cap is 21,000,000 PQ. Genesis may allocate exactly the policy-declared
balances once; the proposed testnet premine is 100,000 PQ. The remaining
20,900,000 PQ can enter circulation only through finalized, evidence-backed
reward transitions. There is no owner mint key, rebasing, hidden allocation or
longest-chain mining race.

### 3. Useful work: separate evidence lanes

Scientific computation and Asgard storage produce typed evidence, not consensus
weight. Scientific rewards require an authoritative project receipt plus a
validator attestation. Storage rewards will require unique-replica commitment,
unpredictable periodic availability challenges, repair evidence and bounded
contract duration. A provider cannot vote more merely by adding disks or jobs.

Each lane has its own reward budget and validation adapter. A malformed or
unavailable adapter stops that lane; it cannot stall VPN traffic or consensus.

### 4. Privacy: network metadata first, ledger privacy later

PQVPN keeps IP addresses out of wallet identities and ledger payloads. Peer IDs
and wallet addresses are unlinkable domain-separated hashes of different public
material. The initial ledger remains publicly auditable. Confidential amounts
or recipients require a proven commitment system, supply-preserving proofs,
view keys and an independent cryptographic audit; until then the UI must not
label transfers anonymous.

Every installed PQVPN instance owns one independently generated hybrid wallet
identity and signs locally: there is no custodial account, recovery server or
operator-held spending key. VPN identity, StrangeNet identity, storage identity
and wallet identity remain separate key domains. A wallet file must be created
once with private-file permissions, must never be silently replaced when
corrupted, and must expose an explicit encrypted backup/restore flow. Reinstalling
without that backup creates a new wallet and cannot recover the old balance.

### 5. Recovery: finalized checkpoints, never automatic history rewriting

Nodes persist checksummed snapshots atomically. A returning node accepts a
recent finalized checkpoint only when its policy digest and quorum certificate
verify, then catches up from that head. Conflicting finalized certificates are
security incidents requiring published evidence and explicit governance—not a
fork-choice score.

## Economic boundary

PQ is an experimental protocol unit. Testnet rewards test accounting and useful
work; they do not imply market price, redemption, profit, yield or ownership in
PQVPN. Credits used for cosmetic social boosts must remain a separate,
non-transferable application balance unless a later audited protocol explicitly
bridges them. Charity claims and purchases require verifiable accounting and
must not be inferred from an on-chain transfer alone.

## What is implemented now

- hybrid wallet addresses and signed transfers with exact nonces;
- policy-authorized subnets and validator identities;
- deterministic supermajority finality and local equivocation rejection;
- capped supply and evidence-backed scientific rewards;
- one-time policy-committed genesis, canonical hash and 100,000 PQ test coverage;
- deterministic audit snapshots and checksummed recovery.

## Required before a public testnet

1. nominate and independently verify the treasury public identity;
2. freeze a canonical transaction/block encoding with cross-language vectors;
3. implement the per-instance wallet keystore, encrypted backup/restore and
   hardware-backed key adapters; raw private keys must never enter config files;
4. implement certified checkpoint catch-up and durable anti-equivocation state;
5. define validator admission, removal and incident governance;
6. add storage challenges without granting storage-weighted voting power;
7. commission protocol, implementation and genesis-ceremony audits;
8. complete jurisdiction-specific legal review before transfer, sale or listing.

The practical validation target is three independently operated validators,
one deliberately partitioned node and reproducible genesis/block hashes across
two implementations. A testnet launch is rejected if either partition can
finalize alone, balances do not reconcile exactly, or a fresh implementation
derives a different byte encoding.
