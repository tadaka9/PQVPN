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

The host should expose only SSH and the configured UDP listener. Use key-only SSH, disable forwarding and X11, keep the firewall default-deny, and run the node without capabilities. The service already applies `NoNewPrivileges`, a closed device policy, a read-only system image, namespace and syscall restrictions, and bounded tasks, memory, and file descriptors. Keep the node configuration and `node_keys.json` owned by `pqvpn` with modes `0640` and `0600` respectively.

The node also limits unauthenticated hybrid-handshake payload size, work per source address, pending handshakes, and total sessions. Signed handshake timestamps must be within five minutes. These bounds are especially relevant to post-quantum deployments because signature and KEM operations make unauthenticated handshake exhaustion more expensive than ordinary packet rejection.

An exit node should set `egress.enabled` to `true`. The default `egress.allow_private_destinations: false` rejects loopback, private, link-local, carrier-grade NAT, benchmark, multicast and reserved destinations before an outbound socket is opened. Keep the same restrictions at the host firewall for defense in depth, and reject outbound SMTP ports from the `pqvpn` service account. A dedicated bootstrap node should leave egress disabled and publish only its discovery role.

The threat model follows deterministic controls rather than an unaudited ML classifier. Relevant research includes [PQC handshake exhaustion and IDS degradation](https://arxiv.org/abs/2607.12504), the [A2PM adversarial NIDS evaluation framework](https://arxiv.org/abs/2502.15561), and the [systematic review of adversarial attacks against intrusion detection](https://arxiv.org/abs/2112.03315). The practical controls here are bounded pre-authentication work, strict parsing, resource limits, least privilege, egress filtering, audit trails and reproducible updates.

Recommended host controls are unattended distribution security updates without automatic reboot, nftables persistence, fail2ban for SSH noise, audit watches on the service, updater, firewall, SSH policy, configuration, and persistent identity, and disabled core-dump storage. Re-run `systemd-analyze security pqvpn-mainnet.service`, `ss -lntup`, `nft list ruleset`, and an external UDP health probe after every host-level change.

The packaged public-node service sends both protocol stdout and stderr to `/dev/null`. This prevents the journal from retaining peer endpoints, session identifiers, destinations, DNS queries or traffic metadata. Do not enable packet logging in the PQVPN firewall chains. Administrative security records remain separate: SSH authentication/fail2ban events, audit records of privileged configuration changes, package operations and updater results. TOFU keeps the minimum persistent public-key trust state needed to recognize a peer; it is not a traffic history. This scope is published in the [no-activity-logs policy](../site/mainnet/no-logs-policy.html).
