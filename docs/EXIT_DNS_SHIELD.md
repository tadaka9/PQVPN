# Exit DNS Shield

PQVPN carries one canonical DNS policy across CLI, TUI and GUI: `off`, `dnscrypt`, `privacy`, `security`, `family`, or `maximum`.

- Every authenticated peer identity maps deterministically to one address in `100.64.0.0/10`.
- The requested policy is covered by the hybrid-signed HELLO. The exit recomputes the internal address from the authenticated Peer ID; it never accepts a client-selected IP.
- Filtered profiles resolve through the virtual service address `100.64.0.1`. The user-space exit forwards only DNS TCP/UDP port 53 at that address to Pi-hole on loopback.
- `off` uses unfiltered public resolvers through the tunnel.
- `dnscrypt` requires a local verified DNSCrypt listener on `127.0.2.1:53` and fails closed when it is missing.

`pqvpn-exit-shield provision` creates the Pi-hole groups and list relationships transactionally. `assign INTERNAL_IP PROFILE` removes the previous group relation and inserts exactly one desired relation, so retries are idempotent. The `off` and `dnscrypt` groups deliberately contain no blocklists.

Pi-hole belongs on an egress node only. A bootstrap must not install it or expose DNS. Pi-hole ports remain loopback/internal; the public firewall needs PQVPN's transport port only. Additional transports such as udp2raw, Shadowsocks, V2Ray and obfs4 require matching client/server components and must remain disabled until their listener, route and firewall health checks pass.

No query history or client IP inventory is returned to the desktop. Aggregate counters can be exposed later through an authenticated, privacy-minimized control event.
