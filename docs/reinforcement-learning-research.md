# Reinforcement-learning research boundary

Status: **research only; not implemented and not authorized for deployment**.

PQVPN's existing `TrafficModel` is an online linear predictor trained by
bounded stochastic gradient descent. It predicts local workload signals and
selects bounded padding/delay. That supervised online update is not a
reinforcement-learning agent, does not explore actions and has no reward loop.

## Question under study

Could a future local policy reduce observable timing regularity or improve
latency/loss trade-offs without learning about people, inspecting content,
weakening fail-closed routing or making network behavior irreproducible?

The answer is currently unknown. Documentation of the question is not approval
to implement it.

## Non-negotiable boundaries

- No payload, destination, DNS query, browsing history, identity, room, social
  reaction or human-engagement signal may enter state, action or reward.
- No reward may rank people, maximize attention, influence beliefs or infer a
  person's vulnerability, value or intent.
- Learning remains local by default. Raw observations, trajectories and
  gradients are not shared or placed on a ledger.
- The packet path never waits for training, model download or consensus.
- Every action stays inside fixed public limits for delay, padding, queue
  memory and drop behavior. A deterministic safe baseline remains available.
- Exploration on live user traffic is prohibited unless a later reviewed
  specification proves an equally safe bounded method. Initial study must use
  offline traces that contain no payload or destination data.
- AIGuardian remains a read-only observer and cannot reward, steer or deploy a
  PQVPN policy.

## Evidence required before any implementation proposal

1. A precise state/action/reward specification and written privacy analysis.
2. A deterministic simulator plus sanitized, reproducible workloads.
3. Comparison against the current bounded predictor and a no-shaping baseline,
   reporting latency, jitter, loss, CPU, memory, padding cost and failure modes.
4. Adversarial evaluation for reward hacking, traffic fingerprint amplification,
   distribution shift, poisoned updates and unsafe oscillation.
5. Shadow-mode replay with no authority over packets, followed by an explicit
   go/no-go review.
6. Versioned policies, signed provenance, bounded rollback and a kill switch
   that restores the deterministic baseline.
7. Independent security and privacy review before any live experiment.

Until every applicable gate has direct evidence, project documentation and UI
must say **RL not implemented**. The words AI, learning, consensus or adaptive
must not be used as substitutes for that claim.

