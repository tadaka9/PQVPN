#!/usr/bin/env python3
"""Keep the unprivileged GUI catalog aligned with the privileged helper."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
gui = (root / "src/monitor/pqvpn_monitor.cpp").read_text(encoding="utf-8")
helper = (root / "packaging/linux/pqvpn-shield-helper").read_text(encoding="utf-8")

profiles = {
    "privacy": ("https://big.oisd.nl/",),
    "security": (
        "https://big.oisd.nl/",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt",
    ),
    "family": (
        "https://big.oisd.nl/",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nsfw.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/gambling.txt",
    ),
    "maximum": (
        "https://big.oisd.nl/",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nsfw.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/gambling.txt",
    ),
}

for profile, urls in profiles.items():
    assert f'"{profile}"' in gui, f"GUI is missing profile id {profile}"
    assert f"{profile})" in helper, f"helper is missing profile id {profile}"
    for url in urls:
        assert url in gui, f"GUI {profile} is missing {url}"
        assert url in helper, f"helper {profile} is missing {url}"

assert "eval " not in helper
assert "curl " not in helper
assert "wget " not in helper
assert "unknown shield profile" in helper
assert '[[ "$profile"' not in helper  # selection is a closed case statement
print("Shield catalog and privileged boundary are aligned")
