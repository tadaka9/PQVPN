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
