# Privacy City integration model

Privacy City is PQVPN's optional 2D pixel interface. It makes the existing
controls easier to discover; it does not replace the node, invent a second
network protocol, or move social state into the VPN's trusted cryptographic
core.

## What is integrated

| City space | Real subsystem | Observable action |
| --- | --- | --- |
| Gateway | Connection preflight and node lifecycle | Opens the one-click, fail-closed connection page |
| Transit Lab | Native/adaptive transport, inner VPN and routing | Opens the same settings used by CLI/TUI configuration |
| Commons | StrangeNet | Selects an authenticated, per-recipient E2E room |
| Shield | Pi-hole profiles | Opens local filtering and aggregate counters |

## Interaction model

Privacy City is now an active session world rather than a decorative preview:

- WASD and the arrow keys move the local avatar; clicks move it to a valid
  walkable point;
- furniture and the Zero-Trust Fountain have collision boundaries, so movement
  cannot pass through scene objects;
- `E`, `Enter` or `Space` activates the current district, while the four large
  district tiles remain directly clickable;
- authenticated peers ease between received positions instead of teleporting;
- accepted StrangeNet text appears temporarily as a bounded speech bubble above
  its authenticated avatar, and sent text appears above the local avatar;
- district discovery is local, session-only visual progress. It is not a token,
  score, reputation signal or behavioral record;
- each session starts with three non-transferable Commons credits and can earn
  at most one more for each newly discovered district. A credit may apply a
  visual highlight to the sender's own delivered message; it never changes
  delivery order, reach, moderation, encryption or network priority;
- emotes and positions use the existing bounded StrangeNet world envelope and
  disappear when the room or process ends.

The scene deliberately has no inventory, trade, purchases, persistent movement
history, location inference or invisible engagement scoring. Commons credits
are not PQ, cryptocurrency, money, reputation or a ledger balance, and reset
with the application session. A peer that is not already authenticated by
PQVPN cannot create an avatar or a speech bubble.

The avatar is a local pseudonymous representation. Other people are rendered
only from authenticated Peer IDs. Participant addresses, movement analytics,
room history and behavioral profiles are not collected or published.

## SEELE and M1M boundary

The source material currently available to this repository does not define a
versioned SEELE or M1M API. Until such a specification is supplied, their
ideas are applied only as product constraints:

- local-first adaptation and explicit human control;
- session-bounded memory instead of a behavioral dossier;
- several specialized subsystems coordinated through one visible state;
- reversible actions, clear feedback and fail-closed networking;
- no claim that an agent, model or interface is conscious.

No hidden inference engine, autonomous identity score, blockchain dependency
or telemetry channel is introduced under either name. A future integration
must define a versioned interface, threat model, data lifetime and tests before
it can affect routing or cryptographic policy.

## Security boundary

The pixel scene may request a navigation or connection action. The existing
configuration validator, process controller, handshake, route gate and DNS
helpers remain authoritative. A scene cannot bypass validation, reveal an IP,
mint trust, accept a peer, or mark a tunnel protected.

PQVPN remains experimental and has not received an independent security audit.
