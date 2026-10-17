# StrangeNet Research Commons

Research Commons is an explicit, local opt-in to donate **at most 1% of one
device's CPU time** to established BOINC science projects. It does not measure
or reserve one percent of the global PQVPN network. That would require global
telemetry, which PQVPN does not collect.

The StrangeNet selector supports astronomy, climate and Earth, medicine and
biology, physics, and mathematics. The controller only resumes a matching
project that the user already attached in BOINC and whose host is on the local
allowlist. It never creates a BOINC account, receives an account key, attaches
a project, enables a GPU, accepts an executable from a peer, or exposes an IP
address. A non-PQVPN `global_prefs_override.xml` is a hard stop rather than a
file to overwrite.

This is real MIMD volunteer computation: independent BOINC work units run
independent programs and data on consenting devices. BOINC remains responsible
for downloading project applications, sandboxing under its configured account,
reporting results, replication and scientific validation. PQVPN only selects
the already-trusted topic and applies the local resource boundary.

## Reward and blockchain boundary

A successful task reported by the local BOINC client creates a deduplicated,
hash-chained receipt claiming **1 PQ**. The receipt contains project URL, result
name and completion time, but no account key or network address. It is not a
coin and cannot be spent, transferred or represented as money.

The repository now contains the fail-closed consensus core described in
[`research-ledger-consensus.md`](research-ledger-consensus.md): parent-authorized
subnets, hybrid-signed attestations, 2/3+1 deterministic quorum certificates,
fork/replay protection, wallets, capped supply and audit snapshots. Minting from
the GUI remains disabled until the remaining runtime gates exist:

1. a project-validator attestation proving that the result was accepted, not
   merely reported by an untrusted client;
2. authenticated proposal/vote/certificate transport and durable certified
   catch-up over PQVPN sessions;
3. reviewed validator admission, rotation and revocation operations;
4. independently audited wallet custody and consensus deployment;
5. adversarial network tests for collusion, partitions and crash recovery.

Without those gates, automatic minting would let a modified client manufacture
unlimited PQ. The GUI therefore labels receipts as pending 1-PQ claims.

## Operator commands

```bash
pqvpn-research-compute status
pqvpn-research-compute enable --topic astronomy
pqvpn-research-compute disable
```

State and receipts are mode `0600` under
`$XDG_STATE_HOME/pqvpn/research-compute` (or `~/.local/state/...`). Disabling
restores the projects' previous suspended state and removes only the preferences
override carrying the PQVPN ownership marker.
