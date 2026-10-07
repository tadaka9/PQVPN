# PQVPN Windows Tunnel Adapter

PQVPN uses its own x64 NDIS 6 layer-3 miniport on Windows. TAP-Windows and
Wintun are disabled in the build and runtime; the node opens only
`\\.\PQVPN_TUN0` unless a development device path is supplied with
`--tunnel-device`.

## Data path

```text
Windows IP stack
      │ NDIS send / receive indication
      ▼
pqvpn_tunnel.sys              kernel mode
  bounded IP packet FIFO
      │ ReadFile / WriteFile, one datagram per operation
      ▼
WindowsOwnTunnel              user mode, C++23
      │
PQVPN encrypted transport
```

The kernel accepts IPv4 and IPv6 datagrams between 20 and 65,536 bytes. The
outbound queue is capped at 1,024 packets and 16 MiB. When either limit is
reached the send completes with a resource error instead of allocating more
kernel memory. User-to-kernel packets are copied into an NDIS receive buffer,
indicated synchronously with `NDIS_RECEIVE_FLAGS_RESOURCES`, then released
after NDIS returns ownership.

The device ACL admits SYSTEM and Administrators. Encryption, peer identity,
routing policy, DNS, traffic shaping, and plugin transports remain in user
mode. Closing the handle cancels the reader and drains queued packets. The node
fails closed on Windows if the adapter was requested but cannot be opened;
`--no-tunnel` explicitly selects relay/exit operation without local tunnelling.

## Build and install

The driver project restores `Microsoft.Windows.WDK.x64` 10.0.26100.6584 and
builds with Visual Studio 2022:

```powershell
msbuild driver\pqvpn_tunnel\pqvpn_tunnel.vcxproj /restore `
  /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
```

This produces an unsigned development package under
`driver\build\x64\Release`. After applying a trusted test or Microsoft
attestation signature, install and assign the default tunnel address from an
elevated shell:

```powershell
.\scripts\windows\Setup-PQVPNAdapter.ps1 `
  -DriverDirectory .\driver\build\x64\Release
```

Windows requires a trusted kernel signature for normal loading. CI therefore
publishes the unsigned driver only as a short-lived diagnostic artifact; it is
not included in a public runnable package until signature verification and the
privileged native tunnel gate succeed.

## Verification

The normal Windows matrix compiles `pqvpn_node.exe` and runs `--help` plus both
configuration smoke tests. The driver job separately builds the actual `.sys`
with the supported WDK, builds the IRP fuzz utility, and validates the HLK test
plan. A real release still requires Microsoft attestation signing and a Windows
host that loads the package and verifies bidirectional traffic, route cleanup,
and clean removal.

GitHub prereleases are tag driven. The `Native build and smoke tests` workflow
publishes a `v*` tag only after every Linux, macOS, and Windows matrix target
has configured, compiled, and passed CLI startup checks. An existing release is
never overwritten.
