# Mainnet operations

The public mainnet node runs as the dedicated `pqvpn` user with its configuration and identity under `/var/lib/pqvpn`. Keeping both files together matters because the node derives the persistent identity path from the configuration directory. The systemd service in `packaging/linux` denies privilege escalation, hides home directories and kernel interfaces, grants write access only to PQVPN state, and limits sockets to IPv4/IPv6.

`pqvpn-mainnet-update` checks the repository's newest release that contains a native archive for the host architecture and `SHA256SUMS`. It downloads both over HTTPS, verifies the exact archive checksum, validates the production configuration with the candidate node, runs its smoke test, installs it under `/opt/pqvpn/releases/<tag>`, and atomically moves `/opt/pqvpn/current`. If the service does not become active, the updater restores the previous symlink and restarts the previous release.

Install the files as root:

```bash
install -o root -g root -m 0755 packaging/linux/pqvpn-mainnet-update /usr/local/sbin/
install -o root -g root -m 0644 packaging/linux/pqvpn-mainnet.service /etc/systemd/system/
install -o root -g root -m 0644 packaging/linux/pqvpn-mainnet-update.service /etc/systemd/system/
install -o root -g root -m 0644 packaging/linux/pqvpn-mainnet-update.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pqvpn-mainnet.service pqvpn-mainnet-update.timer
```

Set `PQVPN_CONFIG=/var/lib/pqvpn/config.json` in `/etc/pqvpn/mainnet-updater.env`. Set `PQVPN_ALLOW_PRERELEASE=0` once stable release packages exist. Other optional variables are `PQVPN_REPOSITORY`, `PQVPN_INSTALL_ROOT`, and `PQVPN_SERVICE`.

The checksum proves that the downloaded archive matches the GitHub release manifest. It does not replace signed releases; the updater should gain signature verification when the project publishes a stable signing key.

This privileged service updater is separate from the manual Privacy Console
flow and does not consume the desktop `*.pqvpnpkg` container. The two trust
boundaries and their current limits are compared in
[`update-system.md`](update-system.md).

The host should expose only SSH and the configured UDP listener. Use key-only SSH, disable forwarding and X11, keep the firewall default-deny, and run the node without capabilities. The service already applies `NoNewPrivileges`, a closed device policy, a read-only system image, namespace and syscall restrictions, and bounded tasks, memory, and file descriptors. Keep the node configuration and `node_keys.json` owned by `pqvpn` with modes `0640` and `0600` respectively.

## Dual-stack readiness

IPv6 readiness is an end-to-end property, not a build flag. A public node may
advertise IPv6 only when all of these checks pass:

1. the provider assigns a stable global IPv6 address and a default route;
2. PQVPN listens on UDP 9090 through an IPv6 or verified dual-stack socket;
3. the host and provider firewalls permit UDP 9090 for IPv6 without opening TCP;
4. an external IPv6 client completes the authenticated PQVPN handshake;
5. relay/egress tests cover IPv4 and IPv6 TCP, UDP, DNS and failure recovery;
6. the registry publishes the bracketed IPv6 endpoint only after those checks.

Use `ss -H -lun4 'sport = :9090'` and `ss -H -lun6 'sport = :9090'` to
inspect socket families. Confirm the address and route with `ip -6 addr show
scope global` and `ip -6 route show default`. A dual-stack-capable binary on a
host with no provider IPv6 is **ready**, not **reachable**, and must remain
listed as IPv4-only. Full-tunnel clients route IPv6 through a verified tunnel
or blackhole it fail-closed; they never leave the physical IPv6 default active
as an accidental bypass.

The node also limits unauthenticated hybrid-handshake payload size, work per source address, pending handshakes, and total sessions. Signed handshake timestamps must be within five minutes. These bounds are especially relevant to post-quantum deployments because signature and KEM operations make unauthenticated handshake exhaustion more expensive than ordinary packet rejection.

## Bounded data-plane tuning

The Linux package installs `60-pqvpn-network-performance.conf`, raising only
the maximum UDP send and receive socket buffers to 4 MiB. PQVPN explicitly
opts its listener into those buffers; unrelated sockets retain their operating
system defaults. This absorbs short authenticated bursts without granting the
daemon unbounded memory. Confirm the effective listener values with
`ss -u -m -p` after a restart and watch the socket's `d` drop counter under a
controlled load test. A growing counter means the host is still discarding
datagrams before PQVPN can authenticate them.

Do not claim WireGuard parity from buffer sizes alone. WireGuard benefits from
an in-kernel data path; PQVPN remains a portable user-space implementation.
Comparable claims require the same hosts, MTU, cipher workload, direction,
concurrency and loss conditions. Linux UDP GSO/GRO can reduce per-packet cost,
but must remain capability-gated and verified against the existing wire-format
tests before deployment.

An exit node should set `egress.enabled` to `true`. The default `egress.allow_private_destinations: false` rejects loopback, private, link-local, carrier-grade NAT, benchmark, multicast and reserved destinations before an outbound socket is opened. Keep the same restrictions at the host firewall for defense in depth, and reject outbound SMTP ports from the `pqvpn` service account. A dedicated bootstrap node should leave egress disabled and publish only its discovery role.

The threat model follows deterministic controls rather than an unaudited ML classifier. Relevant research includes [PQC handshake exhaustion and IDS degradation](https://arxiv.org/abs/2607.12504), the [A2PM adversarial NIDS evaluation framework](https://arxiv.org/abs/2502.15561), and the [systematic review of adversarial attacks against intrusion detection](https://arxiv.org/abs/2112.03315). The practical controls here are bounded pre-authentication work, strict parsing, resource limits, least privilege, egress filtering, audit trails and reproducible updates.

Recommended host controls are unattended distribution security updates without automatic reboot, nftables persistence, fail2ban for SSH noise, audit watches on the service, updater, firewall, SSH policy, configuration, and persistent identity, and disabled core-dump storage. Re-run `systemd-analyze security pqvpn-mainnet.service`, `ss -lntup`, `nft list ruleset`, and an external UDP health probe after every host-level change.

The packaged public-node service sends both protocol stdout and stderr to `/dev/null`. This prevents the journal from retaining peer endpoints, session identifiers, destinations, DNS queries or traffic metadata. Do not enable packet logging in the PQVPN firewall chains. Administrative security records remain separate: SSH authentication/fail2ban events, audit records of privileged configuration changes, package operations and updater results. TOFU keeps the minimum persistent public-key trust state needed to recognize a peer; it is not a traffic history. This scope is published in the [no-activity-logs policy](../site/mainnet/no-logs-policy.html).

---

<!-- pqvpn-project-links -->
[PQVPN website](https://tadaka9.github.io/PQVPN/) ·
[Star the repository](https://github.com/tadaka9/PQVPN) ·
[Support development](https://github.com/tadaka9/PQVPN/blob/main/docs/SUPPORT.md)
