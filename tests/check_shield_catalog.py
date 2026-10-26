#!/usr/bin/env python3
"""Keep the GUI catalog aligned with the exit-node Pi-hole helper."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
gui = (root / "src/monitor/pqvpn_monitor.cpp").read_text(encoding="utf-8")
helper = (root / "packaging/linux/pqvpn-exit-shield").read_text(encoding="utf-8")

profiles = {
    "privacy": ("https://big.oisd.nl/",),
    "security": (
        "https://big.oisd.nl/",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    ),
    "family": (
        "https://big.oisd.nl/",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt",
    ),
    "maximum": (
        "https://big.oisd.nl/",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nsfw.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt",
    ),
}

for profile, urls in profiles.items():
    assert f'"{profile}"' in gui, f"GUI is missing profile id {profile}"
    assert f"PQVPN-{profile}" in helper, f"exit helper is missing group {profile}"
    for url in urls:
        assert url in gui, f"GUI {profile} is missing {url}"
        assert url in helper, f"exit helper {profile} is missing {url}"

assert "pqvpn-shield-helper" not in (root / "CMakeLists.txt").read_text()
assert "pqvpn-shield-helper" not in (root / "packaging/linux/49-pqvpn-network.rules").read_text()
assert "dns-blocklists@latest/domains/" not in gui + helper
assert "eval " not in helper
assert "curl " not in helper
print("Shield catalog and exit-only privileged boundary are aligned")
