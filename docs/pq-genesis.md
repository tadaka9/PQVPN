# PQ genesis and transparent premine

Status: implemented and tested as a protocol primitive; not launched and not a
promise of monetary value.

The surrounding consensus and reward compromise is documented in
[`pq-mesh-ledger-design.md`](pq-mesh-ledger-design.md).

## Proposed testnet constants

| Parameter | Value |
|---|---:|
| Asset identifier | PQ |
| Maximum supply | 21,000,000 PQ |
| Genesis allocation | 100,000 PQ |
| Genesis share | 0.476190% |
| Post-genesis owner mint key | None |

The 100,000 PQ allocation is not created by a later administrative command. It
must appear in `SubnetPolicy::genesis_allocations` before the network starts.
That complete policy is covered by the validator authorization rules. Genesis
then binds the declared address to its Ed25519 and ML-DSA-87 public identity and
derives a canonical SHA3-512/256 identifier. Wallet ordering cannot change the
identifier.

## Fail-closed launch sequence

1. Generate the treasury hybrid keys offline. Never commit or transmit private
   keys.
2. Publish the derived 64-hex wallet address and both public keys through an
   independently authenticated channel.
3. Insert exactly `100000` for that address in the proposed mainnet policy.
4. Have the validator quorum inspect and authorize the complete policy.
5. Reproduce the genesis hash on independent machines and publish the manifest,
   source commit and test evidence before launch.
6. Start only from an empty ledger. Existing balances, wallets, a nonzero head,
   an undeclared address, a duplicate address or supply overflow abort genesis.

The current repository deliberately stops before step 2: no treasury wallet has
been supplied, so no production genesis or spendable PQ exists. This avoids
quietly placing funds under a generated development key.

## Enforced invariants

- total balances always equal total supply;
- genesis supply is immutable and never exceeds total supply;
- total supply never exceeds 21,000,000 PQ;
- the first finalized block must extend the genesis hash;
- initialization is one-shot and cannot add a hidden recipient;
- transfers preserve supply and require both signatures plus the next nonce;
- checkpoints preserve and checksum the genesis hash and supply.

`test_research_ledger` exercises exact allocation, double-initialization,
undeclared-recipient and overflow rejection, signed spending, canonical hashing,
audit visibility and checkpoint recovery.

## Production gates

Before PQ represents transferable value, publish a threat model, custody and
key-recovery policy, validator admission and removal process, reproducible
genesis ceremony, jurisdiction-specific legal review, independent security
audit and incident response plan. The GUI and public site must continue to call
PQ experimental until those gates are complete.
