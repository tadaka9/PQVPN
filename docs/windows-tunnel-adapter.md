# PQVPN Windows Tunnel Adapter — Our Own NDIS Driver

Status: **Phase 1 scaffold implemented (WDM NDIS miniport); compiles + links clean on x64. Phases 2–4 not yet built.** Phase-1 load verification is pending test signing (admin + reboot).
This document is the plan of record for removing every third-party driver
dependency from the Windows data path. It supersedes TAP-Windows6 (OpenVPN)
and Wintun (WireGuard project) as the destination adapter; those remain only
as transitional backends while this work lands.

## Why we build our own

- Windows has **no user-mode virtual NIC facility**. Unlike Linux
  (`/dev/net/tun`) and Apple platforms (Network Extension), a virtual
  network adapter on Windows requires an NDIS kernel driver — there is no
  supported API to create one from user mode.
- Project policy: the entire stack must be auditable under MIT, with no
  binary trust in third-party drivers. TAP-Windows6 and Wintun are both
  maintained by other projects; depending on them means their signing,
  their updates, and their security posture sit inside PQVPN's trust
  boundary. We do not want that.
- The node core is already driver-agnostic: `src/platform/adapter.hpp`
  defines the exception-free `Adapter` contract (open / write / close /
  describe), and routing is handled in user mode by
  `src/routing/route_transaction.cpp` + `peer_route_manager.cpp`. A new
  backend behind that contract is additive; no protocol code changes.

## What we are not doing

- No L2 emulation, no DHCP server inside the driver (TAP-Windows6's model).
  PQVPN assigns its own address and installs its own routes in user mode —
  the kernel component stays a dumb packet pipe.
- No crypto, parsing, or protocol logic in the kernel. The fail-closed
  cryptographic policy lives entirely in user space where it can be tested
  by the CTest suite and the `pqvpn_hard_kernel` gate.

## Architecture

```text
┌────────────────────────────── user mode ──────────────────────────────┐
│ pqvpn_node.exe                                                        │
│   UDP transport · hybrid handshake · onion relay · egress exit        │
│   Adapter contract (src/platform/adapter.hpp)                        │
│     └── WindowsOwnTunnel backend  ← NEW                               │
│           CreateFile(\\.\PQVPN_TUN0) → ReadFile / WriteFile IRPs      │
└───────────────▲───────────────────────────────────────────────────────┘
                │ file object (bounded packet queues, ACL-gated)
┌───────────────┴───────────────────────────────────────────────────────┐
│ pqvpn_tunnel.sys  — NDIS miniport (WDM), medium type NdisMediumIP     │
│   · registers one virtual layer-3 adapter ("PQVPN Tunnel")            │
│   · DriverEntry creates the file object; default-deny DACL               │
│   · ReadFile: kernel→user packet delivery (bounded queue)             │
│   · WriteFile: user→kernel injection (validated length/shape)         │
│   · no protocol logic, no crypto, no DHCP                             │
└───────────────────────────────────────────────────────────────────────┘
```

### Kernel component (`pqvpn_tunnel.sys`)

- NDIS 6.20 miniport built as a classic **WDM** driver (DriverEntry + IoCreateDevice), medium type `NdisMediumIP` (=19, layer-3 TUN semantics). WDM was chosen over WDF for the scaffold: it is a dumb pipe with no framework dependency, keeping the kernel surface minimal.
- Single responsibility: expose one virtual adapter whose data path is a
  pair of bounded FIFO queues bridged to a file object.
- File object security: created in `DriverEntry` (IoCreateDevice) with an explicit default-deny DACL —
  only the PQVPN node's identity may open it; everyone else gets access
  denied. (Phase 2 adds per-handle session binding so two node instances
  cannot share one adapter.)
- IRP boundary validation: length bounds, alignment, and queue-full
  backpressure (read blocks with a timeout; write drops with a status code
  the user-mode backend surfaces as `false`). No unbounded kernel memory.
- Teardown: closing the file object drains queues; removing the driver
  removes the adapter and its routes are owned by user mode (see below),
  so no orphaned state survives in the kernel.

### User-mode component (`WindowsOwnTunnel` backend)

- New source pair `src/platform/windows_own_tunnel.{hpp,cpp}` implementing
  the existing `Adapter` contract — same exception-free semantics as the
  TAP and Wintun backends, so `main.cpp`, tests, and CI need no changes.
- Opens `\\.\PQVPN_TUN0`, runs a reader thread that forwards inbound
  packets to the node's io_context (identical pattern to
  `windows_wintun.cpp`'s receive loop).
- Address assignment: the node assigns its configured tunnel address to
  the adapter via `SetIpAddressEntry` (IP Helper API) — same family of
  calls already used for routes.
- Route installation/removal stays exactly as today: transactional
  default route + per-peer /32 exclusions through `RouteTransaction` and
  `PeerRouteManager`, with rollback on failure. The 2026-09-20 fix to
  `windows_routes.cpp` (`dwForwardProto = MIB_IPPROTO_NETMGMT`) applies to
  this backend unchanged — it is driver-independent IP Helper API usage.

### Control plane — every VPN state, externally callable

The tunnel is not just a pipe: the node exposes a full VPN control surface so that connection state, routing, addressing, DNS, and kill-switch behavior are all queryable and settable from outside (node UI, admin tooling, scripts). Design stance (fail-closed, kernel-minimal): **all policy lives in user mode**; the kernel miniport only registers the adapter, carries packets, and mirrors media up/down so NDIS/OS see the interface track VPN state. None of this is a kernel IOCTL — routes/DNS/IP are Windows IP Helper + registry operations owned by the node's C++ control plane (reusing `RouteTransaction` for atomicity).

#### VPN state machine (all states)

```text
                 connect()                adapter up + routes ok
  DISCONNECTED ─────────────► CONNECTING ────────────────────► CONNECTED
        ▲                          │                                │
        │                     fail / timeout                    disconnect()
        │                          ▼                              ▼
        └──────────────── ERROR ◄────────────────────────── DISCONNECTING
                             │  (peer lost, adapter kept up)
                             └──────────── RECONNECTING ──► CONNECTED

  KILL_ENFORCED: sub-state of {ERROR, DISCONNECTED} while kill switch is ON —
                 all non-tunnel egress is blackholed so nothing leaks.
```

Each state has explicit entry/exit actions and invariants; transitions are the only way system state (routes/DNS/IP) changes. `get_state` reports it; a `state_changed` event is pushed to control-channel subscribers. The kernel mirrors CONNECTED↔up and everything-else↔down via NDIS media indication, so OS interface status always matches the logical VPN state.

#### Capability → mechanism (all user-mode)

| Capability | Mechanism (Windows API) | Fail-closed behavior |
|---|---|---|
| Custom / transversal routes | IP Helper `CreateIpForwardEntry`/`DeleteIpForwardEntry`/`GetIpForwardTable`, wrapped in the existing `RouteTransaction` (atomic, rollback on partial failure) | any step fails → full transaction rolled back; no half-installed route set |
| Endpoint (remote peer) | node config + control API (`set_endpoint`); identity from known peers | unknown/unverified peer refused |
| Startpoint (local IP) | `SetIpAddressEntry`/`AddIPAddress` on the adapter | invalid address rejected; prior value restored on failure |
| Custom IP enumeration | enumerate via `GetUnicastAddressEntry`; assign a bounded set via `AddIPAddress` | count-bounded; all assigned addresses removed on teardown |
| Kill switch | routing policy: ON ⇒ default route → adapter (all traffic in tunnel); on disconnect/error install a blackhole default (next-hop loopback/null) so no egress leaks | fail-closed by construction; prior routes restored only on clean shutdown with kill OFF |
| DNS switching | `SetDNSServerEntry` on the adapter + system resolver order (registry); capture prior resolvers before switching | captured DNS always restored on teardown/error — never leave broken resolution |

#### External control API ("all externally callable")

- **Channel**: local named pipe `\\.\pipe\pqvpn-tun-ctl`, ACL-gated to SYSTEM + Administrators until phase 3 adds the per-node service identity. Owned by the node's user-mode control plane; any process/script (PowerShell, C++, Python) can open it and issue commands — that is what "externally callable" means here.
- **Protocol**: JSON request/response plus an async event stream (`state_changed`).
- **Command set** (each is one externally-callable operation; every mutating op is transactional + fail-closed and returns a structured ok/error/rollback):

| Command | Effect |
|---|---|
| `get_state` | current VPN state, adapter info, active routes/IPs/DNS |
| `connect` / `disconnect` | drive the state machine (entry/exit actions run) |
| `routes_add(prefix,next_hop)` · `routes_remove(prefix)` · `routes_list()` · `routes_set([...])` | transactional route management beyond default+exclusions |
| `set_endpoint(peer\|addr)` · `get_endpoints()` | remote endpoint selection |
| `set_startpoint(ip[,prefix])` · `get_startpoint()` | local interface address |
| `ip_assign([ips...])` · `ip_enumerate()` | custom IP set on the adapter |
| `kill_switch(on\|off)` · `get_kill_switch()` | fail-closed egress policy |
| `dns_switch(on\|off,[resolvers...])` · `get_dns()` | tunnel DNS + restore-on-teardown |

Alternative transports (device-file IOCTLs on a second control device, or a local RPC endpoint) are viable if symmetry with the data pipe is preferred; the command contract above is transport-independent. Default: named pipe for maximum callability and scriptability.

### Driver-free mode (works today, no adapter at all)

`pqvpn_node.exe --no-tap` runs the full node without any virtual adapter:
UDP transport, hybrid handshake, onion relay, and egress exit are all
functional; only local-machine full tunneling is absent. This is a
first-class supported deployment (relay/exit role), verified on Windows
without TAP-Windows6 or Wintun present in the data path.

## Security model

- Kernel surface is minimal by construction: file object + two queues +
  NDIS registration. Nothing in the kernel can interpret PQVPN frames.
- Default-deny ACL on the packet pipe; no local process other than the
  node can read or inject tunnel traffic.
- The driver ships as source in this repository (MIT) — auditable, and
  its behavior is pinned by HLK/DDI compliance tests plus IRP fuzzing
  before any release signature is applied.

## Signing strategy

| Stage | Mechanism | Notes |
|---|---|---|
| Development | Windows test signing (`bcdedit /set testsigning on`) | Requires admin + reboot; dev machines only, never a release path. |
| Release | EV code-signing certificate + Microsoft attestation (Partner Center) | Attested signature is sufficient for modern Windows without WHQL lab submission; target both where feasible. |

## Phases (each phase lands with evidence before the next starts)

1. **Scaffold** — WDK project layout, INF, `DriverEntry` (WDM), file object creation with default-deny DACL. Exit criteria: adapter visible in `netsh interface show interface` under test signing; open succeeds for the node identity and fails for another process. *Status: implemented; compiles + links clean on x64 (valid PE, correct NDIS/Io imports). Load verification pending test signing.*
2. **Data path + state machine + control channel** — bounded ReadFile/WriteFile queues, backpressure, teardown drain; `WindowsOwnTunnel` backend behind the Adapter contract; VPN state machine (all states) owned by the node with kernel media up/down mirroring; external control channel `\\.\pipe\pqvpn-tun-ctl` (ACL-gated) exposing get_state/connect/disconnect + state_changed events. Exit criteria: loopback ping through the adapter with a node-assigned address; CTest coverage of open/write/close lifecycle and the control-channel command contract on Windows CI.
3. **Integration + full control surface** — full-tunnel mode end to end: default route + peer exclusions via `RouteTransaction`; custom/transversal routes (add/remove/list/set, transactional); endpoint/startpoint config + custom IP enumeration; kill switch (fail-closed blackhole when down); DNS switching with guaranteed restore-on-teardown. Two-node e2e (handshake, both directions, clean shutdown with route+DNS rollback) on a self-hosted Windows runner in the functional release gates.
4. **Hardening & signing** — IRP fuzzing (*implemented*), HLK/DDI compliance test infrastructure (*implemented*), EV code-signing certificate setup + Microsoft attestation pipeline, provenance attached to release packaging (feeds `functional-release-gates.yml` evidence contract).

## Transitional backends until phase 3 lands

| Backend | Source | Status |
|---|---|---|
| TAP-Windows6 (OpenVPN driver) | `src/platform/windows_tap.cpp` | transitional; requires the third-party driver to be installed |
| Wintun (WireGuard project) | `src/platform/windows_wintun.cpp` | transitional; requires wintun.dll next to the binary |
| **PQVPN Tunnel (ours)** | phase 1–4 above | destination; no third-party binaries |

## Decisions recorded during phase 1

- **Data-path object**: a kernel **device file** `\\.\PQVPN_TUN0` (created via IoCreateDevice + IoCreateSymbolicLink), not a named pipe. It is the natural NDIS-adjacent surface, gives the backend one well-known open path, and the default-deny DACL gates access to SYSTEM + Administrators until phase 3 adds the per-node service identity.
- **Build tooling**: MSBuild with `PlatformToolset=WindowsKernelModeDriver10.0` (the WDK ships MSBuild props/targets, not a CMake toolchain). Local dev builds set `SkipPackageVerification=true` (this SDK install lacks the 32-bit InfVerif.dll) and `SignMode=off` (unsigned artifact; signing is done out-of-band for loading / release).
- **Architecture**: x64 only. NDIS 6.x miniports are not supported on ARM64 by this SDK (`ndis.h` #errors), so no ARM64 build configuration is shipped.

### Building locally (x64, unsigned)

From the repo root:

```bat
"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" ^
  driver\pqvpn_tunnel\pqvpn_tunnel.vcxproj -p:Configuration=Release -p:Platform=x64
```

Artifacts land in `driver/build/x64/Release/` (`pqvpn_tunnel.sys`, stamped `.inf`, `.cat`). To load the driver for verification, test-sign it and enable test signing (admin + reboot) — see the Signing strategy table above.

## Open questions (still open)

- Adapter naming and enumeration: fixed name `PQVPN Tunnel` vs. per-node instance names when several nodes run on one host.
