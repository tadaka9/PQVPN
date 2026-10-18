# Current research status

Status date: **2026-10-18**. This is a research snapshot, not a release
qualification or a claim of production readiness. Historical release notes
remain historical; this page is the canonical place for the changing research
summary.

## Evidence classes

- **Implemented** means the repository contains the code and focused automated
  evidence for the stated boundary.
- **Observed** means an operator reproduced a runtime fact on the named date;
  it does not convert that host into release evidence.
- **Gated** means design or scaffolding exists but a required independent,
  platform, operational or security proof is still absent.
- **Research only** means no runtime implementation is claimed.

## Repository baseline

The reviewed baseline is commit `4e90b950ac630ab5ff8680a8f2433d4437a1814c`
on `main`, tagged most recently by
`v0.0.23-10172026-David1-beta-ETHICS`. PQVPN remains experimental and has not
completed independent security audit or native release qualification.
The next candidate is deliberately labelled
`0.7.0-10182026-David1-alpha-HONESTY`. Version `0.7.0` is used so the immutable
historical `v0.6-beta-10142026-David0-OTA` remains ordered before it; no tag or
release history is rewritten. The candidate is not a published release until
exact-tag CI and the protected prerelease publisher succeed.

| Area | Evidence-backed state | Remaining boundary |
|---|---|---|
| Hybrid PQ sessions and bounded routing | Implemented in the native source and focused tests | Independent protocol review and hostile-network qualification |
| Adaptive traffic shaping | Local linear predictors use bounded SGD over packet size and inter-arrival timing; payloads, destinations and browsing history are excluded | This is **not reinforcement learning**; path benchmarks and external-engine interoperability remain gated |
| Consensus-guided shaping | Verified, newer, finite weights can bound local choices; forwarding does not wait for consensus | Long-running orchestration, validator operations and adversarial consensus testing |
| Distributed scientific method | Local fail-closed manifest, replication and reproduced/conflict prototype | Authenticated network carriage, admission, publication consent and independent validation |
| Research Commons | Explicit local BOINC opt-in capped at 1% of one device's CPU | Project-validator attestations and audited ledger deployment before minting |
| Research ledger | Core consensus, authenticated envelopes, checkpoints, wallets and capped testnet genesis have source/test evidence | Public treasury nomination, custody, deployment and independent audit; no production coin exists |
| Asgard storage | Local encrypted replicated core, signed capabilities and verified repair | Network storage transport, garbage collection and shared ledger |
| Native releases | Packaging and integrity mechanisms exist | Ten native gate drivers, signed stable releases and clean install/upgrade/rollback evidence |

## Reinforcement-learning boundary

Reinforcement learning is a research question only. It is not present in the
packet path, AIGuardian, Research Commons or the ledger, and must not be
inferred from the existing bounded SGD predictors. The research contract and
minimum gates are in
[`reinforcement-learning-research.md`](reinforcement-learning-research.md).

## Operator observations outside the repository

These observations help prioritize research but are not PQVPN implementation
or release evidence:

- On 2026-10-18, two operator-managed Linux servers answered through their
  configured SSH aliases. Their `pqvpn-mainnet` services and separate
  read-only AIGuardian Node services were active; the designated seed also had
  its bounded TCP seed relay active.
- Those external AIGuardian nodes use **cryptobiosis** as a local, reversible
  pressure/failure policy. Its fixed triggers are memory use at or above 95%,
  disk use at or above 98%, or three consecutive sampling failures. It changes
  the observer's sampling interval from 60 to 300 seconds; it does not stop
  PQVPN, change routes, inspect payloads, learn a policy or grant the observer
  control over another service. Daily Awareness is a separate scheduled
  read-only check, not an RL reward cycle.
- A separate ARM64 Home Assistant host previously reported AIGuardian Cognitive
  v0.2.1 healthy, connected and read-only, with local SQLite memory and Qwen
  disabled; cryptobiosis was inactive at that observation. A fresh
  non-interactive check on 2026-10-18 could not sign with the operator's
  protected local key, so that earlier observation is deliberately not
  promoted to a current runtime claim.
- AIGuardian is an external observer. It has no PQVPN routing authority, does
  not supply consensus weights and is not evidence for any PQVPN security gate.

## Next rigorous research work

1. Publish reproducible latency, loss, CPU and throughput measurements rather
   than comparative performance claims.
2. Complete the threat model and obtain an independent protocol and C++ review.
3. Exercise native install, upgrade, rollback and removal gates on supported
   platforms.
4. Carry research and storage envelopes over authenticated sessions only after
   quotas, admission, recovery and adversarial tests are defined.
5. Keep RL at research-only status until its separate safety contract has
   reproducible offline evidence and an explicit reviewed implementation
   decision.

