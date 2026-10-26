# Exit DNS Shield

PQVPN carries one canonical DNS policy across CLI, TUI and GUI: `off`, `custom`, `privacy`, `security`, `family`, or `maximum`. The wire-level `dnscrypt` value remains a compatibility alias for unfiltered DNS.

`custom` is intentionally different from every preset: the exit receives signed `off`, while the client loads up to eight local regular files (16 MiB combined, 500,000 normalized domains) and optional domain rules. Matching DNS questions are answered locally with NXDOMAIN before they enter the tunnel. The files, rules, and matching decisions never reach Pi-hole. Plain domain lists, hosts-file rows, and common `||domain^` adblock rows are accepted; URLs and remote downloads are not.

- Every authenticated peer identity maps deterministically to one address in `100.64.0.0/10`.
- The requested policy is covered by the hybrid-signed HELLO. The exit recomputes the internal address from the authenticated Peer ID; it never accepts a client-selected IP.
- All profiles resolve through the virtual service address `100.64.0.1`. The user-space exit binds the authenticated tunnel address as its local source and forwards only DNS TCP/UDP port 53 to Pi-hole on loopback, allowing Pi-hole to select the peer's group.
- `off` and the legacy `dnscrypt` alias use no Pi-hole blocklists.
- Pi-hole uses only the local verified DNSCrypt listener on `127.0.2.1:53`; it fails closed when DNSCrypt is missing. The exit template uses cryptostorm's Minisign-verified DeepDNS resolver and relay lists, dynamic `p2` resolver selection, and a dynamically selected anonymizing relay on a distinct network.

`pqvpn-exit-shield provision` creates the Pi-hole groups and list relationships transactionally. `assign INTERNAL_IP PROFILE` removes the previous group relation and inserts exactly one desired relation, so retries are idempotent. The `off` and `dnscrypt` groups deliberately contain no blocklists.

`pqvpn-shield-refresh.timer` updates the exit presets once per day. A randomized delay of up to three hours spreads provider and server load, `AccuracySec=15m` avoids unnecessary wake-ups, and `Persistent=true` performs one catch-up after downtime. The low-priority oneshot runs a single Pi-hole gravity refresh; it does not poll continuously.

Pi-hole belongs on an egress node only. A bootstrap must not install it or expose DNS. Pi-hole ports remain loopback/internal; the public firewall needs PQVPN's transport port only. Additional transports such as udp2raw, Shadowsocks, V2Ray and obfs4 require matching client/server components and must remain disabled until their listener, route and firewall health checks pass.

No query history or client IP inventory is returned to the desktop. Aggregate counters can be exposed later through an authenticated, privacy-minimized control event.
