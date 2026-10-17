# WireGuard or OpenVPN inside PQVPN

PQVPN can establish its native fail-closed full tunnel and then start one
optional VPN client inside that protected path. This is nesting, not an
alternative outer transport: PQVPN owns the first adapter, exit route, DNS
policy and kill switch. WireGuard or OpenVPN starts only after that adapter is
ready and is stopped before PQVPN removes its routes.

```json
"inner_tunnel": {
  "enabled": true,
  "backend": "wireguard",
  "config_path": "/home/user/.config/wireguard/provider.conf"
}
```

`backend` is exactly `wireguard` or `openvpn`. `config_path` must be absolute;
the file stays under the operator's control and PQVPN never prints its
contents. The corresponding `wg-quick` or `openvpn` executable must already be
installed. PQVPN does not download provider software or credentials.

The node and TUI accept the same runtime-only overrides:

```text
--inner-tunnel-backend wireguard|openvpn
--inner-tunnel-config /absolute/path
--no-inner-tunnel
```

The GUI **Transports** page writes the same `inner_tunnel` object. Saving an
already identical policy performs no write. CLI and TUI overrides are pure
assignments and do not mutate the profile.

WireGuard setup uses the symmetric `wg-quick up CONFIG` / `wg-quick down
CONFIG` lifecycle. OpenVPN is supervised as a persistent child process.
OpenVPN profiles must therefore stay in the foreground and must not contain a
`daemon` directive.
Repeated start and stop calls are no-ops, so teardown is safe after partial
startup or more than one shutdown signal.

An inner provider still observes traffic presented to it and can change DNS,
routing and reachability. Nesting increases operational complexity and does
not create guaranteed anonymity. PQVPN remains experimental and has not
received an independent security audit.

