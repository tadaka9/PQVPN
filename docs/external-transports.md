# External transports

The C++23 node supports attaching to an external UDP forwarder. The engine is
not linked into PQVPN. Version 1 uses `mode: attach`: an administrator starts
and supervises the external process independently. There is no shell command
execution, automatic privilege elevation or automatic firewall modification.

## udp2raw

Use `config.udp2raw.json` on the client. Its listener is 127.0.0.1:9090 and its
only bootstrap endpoint is udp2raw's local listener at 127.0.0.1:9091.
Start udp2raw in client mode with that local listener and the remote udp2raw
server address. On the server, udp2raw's destination is the server PQVPN node's
loopback listener. Configure matching keys and raw mode in the external
engine. Prefer udp2raw's configuration file to putting a key in process args.

Official setup and privilege requirements:
[udp2raw upstream](https://github.com/wangyu-/udp2raw).

PQVPN pins its connected UDP socket to the external endpoint. It rejects
outgoing mesh destinations other than that endpoint and receives datagrams
only from the attached engine. If the engine disappears, delivery fails;
PQVPN does not retry through a public UDP endpoint. This is a single-peer
transport, not a multi-peer UDP mux. Configuration rejects a non-loopback
listener, additional bootstrap peers and non-loopback engine endpoints.
Attaching a UDP socket does not prove the external process is ready: the
authenticated PQVPN handshake remains the end-to-end readiness check.

## TCP engines

obfs4, Xray/V2Ray and Shadowsocks are not implemented by this adapter.
Their SOCKS TCP endpoints cannot receive raw PQVPN UDP frames. A separate
authenticated UDP-over-TCP relay and SOCKS integration are required before
those transports can be declared supported. Naming one of these engines in
the UDP configuration is rejected instead of silently sending raw UDP.

## Local traffic shaping

`traffic_shaping.enabled` activates two small online linear predictors,
trained with bounded SGD on packet sizes and arrival intervals. The model
chooses bounded delay and encrypted padding buckets; it does not inspect
payloads, download a model, send telemetry or train against an ISP classifier.
Mode `ai_blockchain` constrains those local predictions with bounded,
quorum-verified distributed weight epochs. Unverified, stale, non-finite or
out-of-range weights are rejected; consensus is never queried in the packet
path. Modes `ai` and `blockchain` remain available for local-only adaptation
or deterministic public policy respectively.
The FIFO preserves nonce ordering, limits memory and drops overflow without
an unshaped fallback. Padding is inside the existing authenticated encrypted
data frame (new frame type 9); malformed padding, tampering and replay are
rejected. Both peers must run the new receiver. Default configuration keeps
legacy frame type 5; shaping is explicitly enabled in the udp2raw example.

This changes size/timing patterns but does not replace an outer transport.
Website access still uses the selected server's existing egress facility.
No interoperability claim with real udp2raw is made until an external-engine
client/server test has run; the C++ tests exercise attachment policy and the
encrypted shaping path.

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)

## Engines on demand

The native console downloads engines only when Install / start is selected. No engine binaries are bundled with PQVPN. `packaging/transports/engines.json` pins upstream URLs, versions and SHA-256 archive hashes. Downloads use HTTPS, have size/time limits, and are verified before extraction or execution. Executables are extracted into a per-user cache; no shell command strings or engine credentials are logged. Stop affects only processes started by this console.

Choose an existing configuration for each engine, then edit it locally or start multiple selected engines. The editor saves atomically with owner permissions and rejects invalid JSON for Shadowsocks, V2Ray and obfs4. obfs4 uses a JSON `environment` object containing its existing `TOR_PT_*` managed-transport settings; state is kept in the engine cache. Matching remote servers and credentials remain operator supplied.

Automatic installers cover Shadowsocks and V2Ray on Linux x86_64/ARM64, macOS Intel/ARM64 and Windows x64; udp2raw on Linux x86_64; the Debian obfs4proxy package on Linux x86_64/ARM64 with compatible libc; and the official DNSCrypt Proxy 2.1.18 archive on Linux x86_64/ARM64. Other combinations fail explicitly. Existing V2Ray configurations requiring GeoIP/GeoSite data must continue referencing their existing data files.

DNSCrypt uses an existing TOML configuration and is launched with
`dnscrypt-proxy -config FILE`. It is a loopback DNS sidecar rather than a PQVPN
packet transport. Starting it does not alter system DNS or PQVPN routes; the
selected fail-closed profile must explicitly use its listener, otherwise the
button reports only that the sidecar is running.

Architecture matching is exact: `aarch64`/`arm64` selects `arm64`, while
`armv7l`/`armhf` selects `armhf`; ARMv6 is a separate unsupported target unless
an explicit catalog entry exists. x86_64, 32-bit x86, RISC-V and LoongArch are
also kept distinct. The installer never falls back from one ABI to another.

Running multiple engines concurrently does not wire them into a valid transport chain. Their existing configurations must link compatible listeners and upstreams. PQVPN currently attaches to a local UDP forwarder; SOCKS and TCP require a separate UDP adapter/relay. Therefore the console distinguishes engine startup from authenticated PQVPN connection, and does not claim unsupported chains provide VPN protection.
