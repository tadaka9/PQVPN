# Conversation coverage audit

This document reconciles the long PQVPN design conversation with the source
tree. **Implemented** means code plus focused test or native build evidence;
**gated** means enabling the feature requires platform authority, external
infrastructure, legal configuration or security evidence the repository cannot
manufacture.

## Implemented surfaces

| Requirement family | Current implementation | Evidence boundary |
|---|---|---|
| Bootstrap + mainnet exit | Explicit roles, registry, updater and service units | Fleet deployment is separate from source correctness |
| Fast/stable data plane | TCP backpressure, adaptive window, bounded queues, replay bitmap and socket buffers | Reproducible path benchmarks remain required |
| GUI reliability | Raster-safe scrolling, close-to-tray, action smoke checks, one-click preflight and honest phases | Native CI determines platform support |
| StrangeNet social | Text, replies, DM, voice, reactions, profiles, pinned groups and notifications | Live-session mesh; no asynchronous global-delivery claim |
| Pixel Commons | Authenticated E2E movement, four zones, fixed emotes and Peer-ID avatars | Session-only; no authoritative inventory or economy |
| Private usage signal | Active, process peak and established-session aggregate counters | No IP, destination, duration, room or volume history; resets on restart |
| DNS Shield | OISD/HaGeZi presets, bounded regex, aggregate Pi-hole counters and explicit-target speed test | Filtering cannot guarantee child safety |
| External/inner transports | Architecture-aware sidecars plus config-driven WireGuard/OpenVPN | A running helper does not prove traffic uses it |
| Exit selection | Health/capacity weighted assignment, flow affinity and fail-closed choice | More peers help only when independently healthy |
| Flux console | Aggregate fleet health over hardened SSH aliases | No participant/payload telemetry or billing-provider access |
| Asgard core | Encrypted chunks, rendezvous placement and local replication quorum | Network transport, repair and public cloud are gated |
| Releases/site | Future development, protected promotion, versioned registry and refreshed metadata | Automation alone creates qualifying releases |

## Gated or deliberately not claimed

| Request | Why it is not silently enabled | Smallest honest next gate |
|---|---|---|
| Android/iOS full VPN | VPNService/Network Extension, signing and device tests are absent | Implement adapters and pass device leak/rollback qualification |
| Asgard blockchain/credits | Asgard has no consensus, wallet or payment processor | Specify/test ledger, custody, refunds and 90/10 accounting; review it |
| Real credit purchase | Charity, jurisdiction, fee denominator and settlement evidence are unspecified | Configure charity + processor + terms; remain fail-closed until then |
| Storage over PQVPN | Current storage peers are local/operator-mounted roots | Signed capabilities, quotas, authenticated transport and hostile tests |
| Guaranteed anonymity | Endpoint compromise and traffic analysis remain possible | Publish threat model and complete independent audit |
| LAN access with WAN fail-closed on every OS | Policy exists, native WFP/route/DNS proof does not | Implement policy engine and capture-based LAN on/off qualification |
| Global asynchronous StrangeNet | Origin-signed store-and-forward and abuse controls do not exist | Bounded envelopes, expiry, quotas and adversarial tests |
| Persistent game economy | Conflicts with zero-telemetry/session-only world and introduces financial abuse | Keep exploration local unless a reviewed opt-in economy exists |
| Faster than WireGuard | No reproducible benchmark supports the claim | Publish median/p95 throughput, latency, loss and CPU comparisons |

## Conflict resolutions

- Zero telemetry wins over participant tracking. Only aggregate,
  process-lifetime counters are exposed.
- “No demo” means the desktop world uses the real StrangeNet session; the
  website explains it but never fakes a live peer connection.
- Metin2/Habbo are interaction references only. PQVPN uses original names,
  visuals and mechanics and imports no proprietary asset or code.
- The VPN remains usable without payment. Storage hosting, exit operation and
  credits never grant access to cryptographic identity keys.
- Accurate claims win over optimistic marketing: experimental, unaudited and
  preview labels remain until evidence changes.

Update this audit only when a gate obtains direct evidence. A GUI control,
roadmap sentence or workflow file alone is not a finished security feature.
