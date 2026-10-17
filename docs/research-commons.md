# Path Quilt Research Commons

Research Commons is an explicit, local opt-in to donate **at most 1% of one
device's CPU time** to established BOINC science projects. It does not measure
or reserve one percent of the global PQVPN network. That would require global
telemetry, which PQVPN does not collect.

The StrangeNet selector supports astronomy, climate and Earth, medicine and
biology, physics, mathematics, and experimental decentralized modular AI/AGI.
“Newest algorithm first” means the newest independently evidenced workload
offered by an already trusted project; novelty is not treated as evidence, and
the authoritative BOINC project scheduler still decides which work unit the
client receives. The controller only resumes a matching
project that the user already attached in BOINC and whose host is on the local
allowlist. It never creates a BOINC account, receives an account key, attaches
a project, enables a GPU, accepts an executable from a peer, or exposes an IP
address. A non-PQVPN `global_prefs_override.xml` is a hard stop rather than a
file to overwrite.

Researchers can share a paper title and DOI or HTTPS reference with their
current StrangeNet audience. That citation follows the same E2E, session-only
delivery rules as chat and does not upload the PDF. Publishing a paper into the
public Asgard Commons is deliberately a separate operation: it must show the
content hash, size and licence, record affirmative author/uploader consent, and
warn that replicated public data may not be practically retractable.

This is real MIMD volunteer computation: independent BOINC work units run
independent programs and data on consenting devices. BOINC remains responsible
for downloading project applications, sandboxing under its configured account,
reporting results, replication and scientific validation. PQVPN only selects
the already-trusted topic and applies the local resource boundary.

## Reward and blockchain boundary

A successful task reported by the local BOINC client creates a deduplicated,
hash-chained receipt claiming **1 PQC (Path Quilt Coin)**. New v2 receipts retain
only project and result digests plus an hour-bucketed completion time: no URL,
result name, account key or network address. Compatibility verification remains
for existing v1 receipts. A pending receipt is not a coin and cannot be spent,
transferred or represented as money.

StrangeNet may also originate a contribution claim for useful community work,
such as independently reproduced classification, a validated correction or a
successful moderation appeal. Sending messages, collecting reactions, staying
online, exploring the world or consuming attention never qualifies. A social
claim needs a permitted project class, two independent confirmations and a
hybrid signature from an admitted validator before it can become a scientific
attestation.

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
unlimited PQC. The GUI therefore labels receipts as validator-pending PQC.

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
