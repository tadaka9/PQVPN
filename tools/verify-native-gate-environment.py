#!/usr/bin/env python3
"""Non-authoritative native release environment probe.

Reports concrete missing host/build/signing prerequisites. A green probe is
NOT privileged PQVPN traffic, lifecycle, platform signing, or an attestation.
Nothing in this report may be copied to schema-2 qualification evidence.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import shutil
import sys

ARCH_ALIASES = {
    "amd64": "x86_64", "x64": "x86_64", "x86_64": "x86_64",
    "arm64": "arm64", "aarch64": "arm64",
}
TARGET_PACKAGERS = {
    "linux": (),
    "deb": ("dpkg-deb", "dpkg"),
    "rpm": ("rpm", "rpmbuild"),
    "arch": ("makepkg", "pacman"),
    "appimage": ("appimagetool", "unsquashfs"),
    "macos": ("codesign", "pkgutil", "spctl", "xcrun"),
    "windows": ("signtool.exe", "pnputil.exe", "sc.exe"),
}
TARGETS = tuple(
    f"{family}-{arch}" for family, arches in {
        "linux": ("x86_64", "arm64"),
        "deb": ("x86_64", "arm64"),
        "rpm": ("x86_64", "arm64"),
        "arch": ("x86_64",),
        "appimage": ("x86_64", "arm64"),
        "macos": ("x86_64", "arm64"),
        "windows": ("x86_64", "arm64"),
    }.items()
)


def privileged(os_name):
    if os_name == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def inspect(target, *, os_name=None, machine=None, tool_lookup=None,
            elevated=None, tun_exists=None):
    if target not in TARGETS:
        raise ValueError(f"Unrecognized mandatory target: {target}")
    family, arch = target.rsplit("-", 1)
    current_os = os_name or platform.system()
    current_arch = ARCH_ALIASES.get(
        (machine or platform.machine()).lower(), "unsupported")
    lookup = tool_lookup or shutil.which
    expected_os = {"windows": "Windows", "macos": "Darwin"}.get(family, "Linux")
    blockers = []

    def fail(code, reason):
        blockers.append({"code": code, "reason": reason})

    if current_os != expected_os:
        fail("wrong_os", f"Requires {expected_os}; host is {current_os}")
    if current_arch != arch:
        fail("wrong_arch", f"Requires {arch}; host is {current_arch}")

    for executable in TARGET_PACKAGERS[family]:
        if not lookup(executable):
            fail("tool_missing", f"Native package/signature tool missing: {executable}")
    if family in {"linux", "deb", "rpm", "arch", "appimage"}:
        if not lookup("ip"):
            fail("tool_missing", "iproute2 is required for real route and rollback tests")
        has_tun = Path("/dev/net/tun").is_char_device() if tun_exists is None else tun_exists
        if not has_tun:
            fail("tun_missing", "A real Linux /dev/net/tun character device is required")
    admin = privileged(current_os) if elevated is None else elevated
    if not admin:
        fail("not_elevated", "A privileged native runner is required for system tunnel tests")

    # This probe does NOT infer platform signature or provenance status from
    # tool installation, environment variables, or a token's privilege.
    return {
        "target": target,
        "runner_os": current_os,
        "runner_arch": current_arch,
        "environment_ready": len(blockers) == 0,
        "qualification_passed": False,
        "scope": "host preconditions ONLY; native tunnel, rollback, signed lifecycle and provenance remain mandatory",
        "blockers": blockers,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = inspect(args.target)
    payload = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if result["environment_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
