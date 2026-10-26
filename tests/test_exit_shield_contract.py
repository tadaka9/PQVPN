#!/usr/bin/env python3
from pathlib import Path


root = Path(__file__).resolve().parents[1]
helper = (root / "packaging/linux/pqvpn-exit-shield").read_text()
main = (root / "src/main.cpp").read_text()
forwarder = (root / "src/modules/egress_forwarder.cpp").read_text()
sudoers = (root / "packaging/linux/pqvpn-exit-shield.sudoers").read_text()

assert "dns-blocklists@latest/domains/" not in helper
for name in ("tif", "pro", "nsfw", "gambling"):
    assert f"dns-blocklists@latest/adblock/{name}.txt" in helper

assert '/usr/sbin/ip address replace "$ip/32" dev lo' in helper
assert '::execl("/usr/bin/sudo", "sudo", "-n", helper, "assign"' in main
assert "local_dns ? c_addr.to_v4()" in forwarder
assert "f->sock->bind(asio::ip::tcp::endpoint(c_addr, 0)" in forwarder

rule = "pqvpn ALL=(root) NOPASSWD: /usr/lib/pqvpn/pqvpn-exit-shield assign *"
assert rule in sudoers
assert len([line for line in sudoers.splitlines() if line and not line.startswith("#")]) == 1

