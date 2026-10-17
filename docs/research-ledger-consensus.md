# PQVPN research ledger and subnet consensus

Status: protocol core, authenticated PQVPN datagram carriage, checkpoint
recovery/pruning helpers, and a fail-closed signed project adapter are
implemented and tested. Runtime orchestration, project-side signing-key
deployment and an independent audit remain release gates.

## Mainnet-derived subnets

A `SubnetPolicy` names its parent, physical operator, operator Peer ID, bounded
rule set, allowed scientific projects, transfer policy, per-block reward bound,
validator identities, epoch, maximum supply and reward per accepted result. A
child such as `mainnet/research-eu` is accepted only when:

- its name is a strict descendant of `mainnet`;
- the operator has an authenticated 64-hex Peer ID;
- at least `floor(2N/3)+1` validators from the parent policy sign the complete
  canonical child policy using both Ed25519 and ML-DSA-87;
- its epoch is not older than the parent epoch.

An operator label is administrative accountability, not unilateral control.
The operator cannot change rules, project allowlist, transfers, validators,
supply or rewards without a new parent-quorum authorization. These are enforced
while validating attestations, blocks and transfers rather than displayed as
descriptive metadata.

## Scientific attestations

An attestation binds subnet, canonical job ID, result digest, beneficiary wallet,
project, completion time and validator identity. Both signatures cover the same
domain-separated canonical payload. A local BOINC exit status is insufficient.
`ProjectAdapter` accepts a result only when an allowlisted project signs the
canonical valid-result receipt with both Ed25519 and ML-DSA-87; a PQVPN
validator then translates that receipt into the attestation format.
Participating projects still need to deploy and rotate those signing keys—the
generic unsigned BOINC Web RPC is not mint authority.

## Deterministic finality

A block commits its exact subnet, epoch, height, previous hash, proposer and
ordered attestation digests. It finalizes only with unique valid votes from
`floor(2N/3)+1` members of the subnet validator set. Nodes accept exactly
`height + 1` over their current head. They do not choose a longest fork.

Assuming fewer than one third of validators are Byzantine and honest validators
never double-sign, two conflicting quorum certificates cannot both exist: the
quorums overlap in an honest signer. `VoteGuard` records `(subnet, height,
validator) -> block hash` and rejects local equivocation. During a partition,
any side without quorum stops; it does not mint speculatively. Rejoining nodes
must obtain the certified chain from their last finalized head.

Replay defenses are layered:

- monotonic block height and exact previous hash;
- one finalized use of each canonical scientific job ID;
- unique validator identities in every quorum certificate;
- wallet nonces increasing by exactly one;
- domain-separated signatures for policy, attestation, block and transfer.

## Wallet, genesis and supply

Wallet addresses are the first 256 bits of SHA3-512 over the domain tag and the
Ed25519 plus ML-DSA-87 public keys. Registration proves the address matches both
keys. A subnet policy may commit an explicit address-to-amount genesis map.
Initialization accepts exactly those public identities, canonicalizes their
order, derives a domain-separated genesis hash and can succeed only once on an
empty ledger. The genesis supply is included in the cap and audit snapshot.
There is no privileged post-genesis mint method.

The proposed PQ testnet commits a 21,000,000 PQ maximum and exactly 100,000 PQ
at genesis (0.476190% of the cap). The final recipient wallet is intentionally
not embedded until its public hybrid identity is nominated and independently
verified. There is therefore no live premine yet. After genesis, minting occurs
only while applying a finalized block containing valid attestations. The
per-result reward is a subnet policy field, currently one PQ; checked arithmetic
prevents overflow and total supply cannot exceed the policy cap. Transfers
require both wallet signatures, sufficient balance and the next nonce.
Transfers never change total supply.

The deterministic audit snapshot exposes subnet, policy digest, height, head,
supply cap, current supply and balances. `verify_invariants()` independently
reconciles all balances with supply after every finalized block and transfer.

## Remaining production gates

The following are not represented as complete:

1. connect the implemented research datagram handler, ledger and checkpoint
   helpers to the long-running node orchestration and certified catch-up flow;
2. add directory fsync, crash/fault-injection coverage, state bounds and
   externally verifiable snapshot proofs around atomic checkpoint replacement;
3. deployment of project-side signing keys and rotation/revocation procedures;
4. validator admission economics or another reviewed Sybil-resistance policy;
5. third-party protocol and implementation audit.

An independent audit cannot be authored or approved by the implementation
team. Auditors should receive the threat model, canonical test vectors, source,
build instructions, adversarial tests and an immutable commit identifier. Until
their signed report and remediation record are published, the project must say
“not independently audited.”
