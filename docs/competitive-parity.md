# Desktop VPN competitive parity plan

PQVPN competes on verifiable protection, not on the number of switches in its interface. This plan uses current first-party documentation from established privacy VPNs as a market baseline and turns each capability into a release gate.

## Expected desktop baseline

Mature desktop clients expose a normal and persistent kill switch, application and IP split tunnelling, automatic reconnection, protocol selection, DNS leak protection, multi-hop paths, server selection and an installed application with automatic updates. Proton documents these together in its Windows client, including Smart Protocol, WireGuard, OpenVPN, Secure Core, custom DNS and comprehensive IPv4/IPv6 leak protection. Mullvad supports application exclusions on desktop but deliberately avoids inverse split mode because of leak risk. IVPN documents both normal and inverse application modes and calls out their DNS consequences.

References:

- [Proton VPN Windows capabilities](https://protonvpn.com/support/install-windows-vpn)
- [Proton advanced kill switch](https://protonvpn.com/support/advanced-kill-switch)
- [Proton split tunnelling](https://protonvpn.com/support/protonvpn-split-tunneling)
- [Mullvad split tunnelling and secure defaults](https://mullvad.net/en/help/split-tunneling-with-linux-advanced)
- [IVPN split tunnel behavior and DNS limits](https://www.ivpn.net/knowledgebase/general/split-tunnel-faq/)

## PQVPN parity gates

| Priority | Capability | Current state | Gate for claiming support |
|---|---|---|---|
| P0 | Clean Windows install | MSI exists; proprietary driver is not shipped because it is unsigned | Signed driver installs and rolls back with the MSI on a clean supported Windows VM |
| P0 | One-click protected connection | Peer and route state are now distinct in the GUI | GUI test proves install → preflight → connect → exit-IP change → disconnect without a shell |
| P0 | IPv4, IPv6 and DNS leak protection | Windows IPv4 default and IPv6 tunnel/blackhole are transactional; DNS mutation is incomplete | Packet capture proves no physical egress during connect, peer change, sleep, crash and recovery |
| P0 | Kill switch | Route startup now fails closed; persistent filtering is not implemented | WFP on-demand and always-on modes pass reboot, crash and interface-change tests |
| P0 | Automatic recovery | Bootstrap retries exist | GUI shows bounded reconnect with kill switch held, endpoint rotation and a clear terminal error state |
| P1 | Split tunnelling | Design contract exists | WFP app rules plus CIDR include/exclude rules pass DNS and process-lifecycle leak tests |
| P1 | LAN access | Must remain disabled by default | Enumerated on-link prefixes are the only exception and are visible in GUI and diagnostics |
| P1 | Server and route selection | Helsinki bootstrap and Stockholm exit are a pilot topology | Signed directory, health checks, latency samples and deterministic geo/load selection drive the GUI |
| P1 | Profiles and auto-connect | Not implemented | Trusted/untrusted network rules and startup profiles are user-controlled and reversible |
| P1 | Release updates | Manual release check, double-hashed custom package, and Linux service rollback exist | Signed native packages, verified provenance, staged desktop upgrade/rollback and clean-VM lifecycle tests pass on every supported target |
| P1 | WireGuard/OpenVPN | Launch adapters exist but lifecycle is incomplete | Availability preflight, safe secret handling, readiness probe and guaranteed teardown pass native tests |
| P2 | Smart protocol | Policy controller exists but is not wired to the data path | Real UDP/TCP lanes switch under controlled loss/blocking without changing the authenticated session |
| P2 | Shadowsocks/V2Ray/udp2raw | udp2raw attach mode exists; the others are not integrated | Supervised binaries, pinned versions, local authenticated control and interoperability tests pass |
| P2 | Multi-hop | Mesh primitives exist | User-selected entry/exit path is cryptographically bound and independently observable |
| P2 | DNS filtering | Not implemented | Optional signed blocklists, local cache isolation and bypass prevention pass false-positive and leak tests |
| P3 | External audit and reproducible release | CI and CodeQL exist | Reproducible binaries, SBOM/provenance, independent audit and public remediation ledger cover the client, service and driver |

## Product rules

The main screen stays simple: choose a recommended route and connect. Advanced policy belongs in a separate security view. Every exception states which traffic can leave outside PQVPN. Settings that require reconnection say so before saving. Unsupported capabilities remain absent rather than appearing disabled or being described as available.

The status hierarchy is fixed: **Disconnected**, **Connecting**, **Peer ready · securing routes**, **Protected**, **Reconnecting**, and **Blocked**. Relay mode uses **Mainnet connected · relay mode** and never shares the protected visual state. The tray, diagnostics and main window derive their label from the same state.

Release notes must separate compiled, integration-tested and production-verified capabilities. No protocol or leak-protection claim is published from a unit test alone.

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)
