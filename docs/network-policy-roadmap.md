# Leak protection, kill switch and split tunnelling

This document is the implementation contract for PQVPN's desktop network policy. A GUI label is not evidence that traffic is protected: the node must report each enforced operating-system state before the console may show **Protected**.

## Current enforced baseline

On Windows, local-tunnel startup fails closed unless the native adapter opens, has an IPv4 address, a pre-VPN physical default route can be captured, every known peer can be pinned outside the tunnel, and the IPv4 default plus either a tunnelled or blackholed IPv6 default can be committed as one owned route transaction. The GUI only shows **Protected** after both an authenticated peer event and a `tunnel.ready` event with `fail_closed=true`.

Relay mode is deliberately separate. It can authenticate peers and carry StrangeNet, but the GUI states that local system traffic is not tunnelled. Before launch, the GUI validates the configuration, checks the Windows driver, fingerprints both the configuration and executable, and refuses to start if either file changes.

This baseline does not yet override more-specific physical LAN routes and does not provide an always-on disconnected kill switch. Those cases require the policy engine below.

## Policy model

The network policy will use these explicit settings:

```json
{
  "network_policy": {
    "kill_switch": "on-demand",
    "lan_access": false,
    "split_tunnel": {
      "mode": "full",
      "include_cidrs": [],
      "exclude_cidrs": [],
      "include_apps": [],
      "exclude_apps": []
    }
  }
}
```

`kill_switch` accepts `off`, `on-demand`, or `always-on`. `lan_access` is false by default. Split mode accepts `full`, `include`, or `exclude`; conflicting or overlapping entries fail validation. Application rules use canonical executable paths and publisher identity where the platform exposes it. Hostnames are resolved into bounded, expiring IP sets and never silently broadened.

## Windows enforcement

Windows Filtering Platform (WFP) is the authority for the kill switch and application split rules. Filters are installed by the privileged service, grouped under one provider and sublayer, and updated in a WFP transaction. The default block becomes active before route or DNS mutation. Narrow permits then cover the selected PQVPN executable, authenticated bootstrap and peer endpoints, DHCP, and the configured local-network exception. Loopback remains available.

Route transactions remain responsible for tunnel defaults, peer host-route exclusions and CIDR split rules. With LAN access disabled, connected physical prefixes receive more-specific tunnel or block coverage so an existing RFC1918 or IPv6 on-link route cannot bypass the VPN. With LAN access enabled, only the enumerated on-link prefixes are preserved; the GUI displays this exception beside the protected state.

DNS changes are part of the same state transition. The service captures the real per-interface resolver state, applies tunnel resolvers, blocks port 53 and encrypted-DNS bypass outside the selected policy where feasible, flushes caches, and restores the captured state during rollback. A synthetic resolver list is never acceptable.

## Transaction order

Connect follows one order:

1. Validate configuration, driver, privileges, executable identity and endpoint set.
2. Create the WFP transaction and activate the default-deny filter set.
3. Add peer endpoint permits and physical peer host routes.
4. Open and configure the tunnel adapter.
5. Apply DNS and full or split route transactions.
6. Verify the effective route table, DNS state, IPv4/IPv6 egress and peer reachability.
7. Emit `tunnel.ready`; the GUI may now show **Protected**.

Any failure rolls back owned DNS and route changes while retaining the blocking policy until the prior network state is verified. Disconnect reverses the order. `always-on` keeps the WFP block after disconnect; `on-demand` removes it only after cleanup succeeds.

## GUI requirements

The console presents separate states for process startup, peer authentication, adapter readiness, route readiness, DNS readiness and kill-switch readiness. It must never infer them from text logs. LAN and split-tunnel exceptions appear next to the connection state and in the tray tooltip. Each policy change invalidates the prior validation and requires a new preflight.

The Connect action stays disabled when the driver is missing, access is denied, a configured backend executable is unavailable, split rules are ambiguous, DNS capture fails, or an always-on kill switch cannot be installed. Relay mode remains available as an explicit non-tunnelling choice.

## Release gates

A Windows release is eligible only after a clean virtual machine installs the MSI and signed driver, connects through the GUI, observes an exit-IP change, and passes packet-capture tests for IPv4, IPv6, DNS, WebRTC-relevant routes, LAN enabled/disabled, sleep/resume, interface changes, process crash, service crash, peer rotation and uninstall. Tests must demonstrate that only declared split or LAN exceptions leave through a physical interface. Route, DNS and WFP state must match the pre-install snapshot after cleanup.

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)
