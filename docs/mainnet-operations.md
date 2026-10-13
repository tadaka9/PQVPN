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

Recommended host controls are unattended distribution security updates without automatic reboot, nftables persistence, fail2ban for SSH noise, audit watches on the service, updater, firewall, SSH policy, configuration, and persistent identity, and disabled core-dump storage. Re-run `systemd-analyze security pqvpn-mainnet.service`, `ss -lntup`, `nft list ruleset`, and an external UDP health probe after every host-level change.
