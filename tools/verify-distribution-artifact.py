#!/usr/bin/env python3
"""Native package *artifact* gate, not a privileged VPN release qualification.

This verifies real bytes/metadata produced for Linux distributions. A PASS here
does not satisfy tunnel, install/upgrade/rollback, signature or provenance gates.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LINUX_TARGETS = {
    "linux-x86_64": ("tar", "x86_64"),
    "linux-arm64": ("tar", "arm64"),
    "deb-x86_64": ("deb", "x86_64"),
    "deb-arm64": ("deb", "arm64"),
    "rpm-x86_64": ("rpm", "x86_64"),
    "rpm-arm64": ("rpm", "arm64"),
    "arch-x86_64": ("arch", "x86_64"),
    "appimage-x86_64": ("appimage", "x86_64"),
    "appimage-arm64": ("appimage", "arm64"),
}
ELF_MACHINE = {"x86_64": 62, "arm64": 183}


class GateError(ValueError):
    pass


def run(*args, timeout=60, cwd=None):
    try:
        return subprocess.check_output(args, cwd=cwd, text=True,
                                       stderr=subprocess.STDOUT, timeout=timeout).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"Command failed: {args[0]}: {exc}") from exc


def native_arch():
    machine = platform.machine().lower()
    return {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)


def assert_elf(data, arch):
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[5] not in (1, 2):
        raise GateError("Missing or invalid ELF binary")
    machine = int.from_bytes(data[18:20], "little" if data[5] == 1 else "big")
    if machine != ELF_MACHINE[arch]:
        raise GateError(f"Wrong ELF architecture: {machine}; expected {arch}")


def assert_version(version):
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version):
        raise GateError("Unsafe release version")


def version_with_bash(function, version):
    if function not in {"pqvpn_debian_version", "pqvpn_arch_version"}:
        raise GateError("Unexpected version conversion")
    script = ROOT / "packaging/version-functions.sh"
    return run("bash", "-c", 'source "$1"; "$2" "$3"', "bash",
               str(script), function, version)


def check_tar(package, version, arch):
    if not package.name.endswith(".tar.gz") or version not in package.name:
        raise GateError("Expected versioned tar.gz release archive")
    try:
        with tarfile.open(package, "r:gz") as archive:
            members = archive.getmembers()
            nodes = []
            for item in members:
                parts = Path(item.name).parts
                if not parts or item.name.startswith("/") or ".." in parts:
                    raise GateError(f"Unsafe archive entry: {item.name}")
                if item.issym() and (item.linkname.startswith("/") or
                                     ".." in Path(item.linkname).parts):
                    raise GateError(f"Unsafe archive symlink: {item.name}")
                if item.islnk() or item.isdev() or item.isfifo():
                    raise GateError(f"Unexpected archive entry type: {item.name}")
                if item.isfile() and item.name.endswith("/bin/pqvpn_node"):
                    nodes.append(item)
            if len(nodes) != 1:
                raise GateError("Expected exactly one packaged pqvpn_node")
            stream = archive.extractfile(nodes[0])
            if stream is None:
                raise GateError("Cannot inspect packaged pqvpn_node")
            assert_elf(stream.read(20), arch)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise GateError(f"Unusable tar archive: {exc}") from exc


def check_deb(package, version, arch):
    if package.suffix != ".deb":
        raise GateError("Expected a Debian .deb archive")
    metadata = run("dpkg-deb", "-f", str(package), "Package", "Version", "Architecture")
    fields = metadata.splitlines()
    if len(fields) != 3 or fields[0] != "pqvpn":
        raise GateError(f"Wrong Debian package name/metadata: {metadata}")
    expected_version = version_with_bash("pqvpn_debian_version", version)
    expected_arch = {"x86_64": "amd64", "arm64": "arm64"}[arch]
    if fields[1:] != [expected_version, expected_arch]:
        raise GateError(f"Incorrect Debian version or architecture: {fields[1:]}")
    with tempfile.TemporaryDirectory(prefix="pqvpn-deb-gate-") as tmp:
        run("dpkg-deb", "-x", str(package), tmp, timeout=120)
        root = Path(tmp)
        binary = root / "usr/lib/pqvpn/bin/pqvpn_node"
        if not binary.is_file():
            raise GateError("Debian package lacks the deployed node")
        assert_elf(binary.open("rb").read(20), arch)
        if not (root / "etc/pqvpn/config.json.example").is_file():
            raise GateError("Debian package lacks operator configuration example")
        launcher = root / "usr/bin/pqvpn_node"
        if not launcher.is_symlink() or launcher.resolve() != binary.resolve():
            raise GateError("Debian package lacks the expected safe launch symlink")
        if arch == native_arch():
            actual = run(str(binary), "--version", timeout=30)
            if actual != f"PQVPN {version}":
                raise GateError(f"Packaged node reports unexpected version: {actual}")


def check_rpm(package, version, arch):
    if package.suffix != ".rpm":
        raise GateError("Expected RPM archive")
    raw = run("rpm", "-qp", "--queryformat",
              r"%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n", str(package))
    fields = raw.splitlines()
    if len(fields) != 4 or fields[0] != "pqvpn":
        raise GateError("Invalid RPM name or metadata")
    expected = re.match(r"^(\d+)\.(\d+)-(?:alpha|beta)-\d+-", version)
    if expected is None:
        expected = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
        numeric = ".".join(expected.groups()) if expected else None
    else:
        numeric = ".".join(expected.groups()) + ".0"
    if fields[1] != numeric or fields[3] != {"x86_64": "x86_64", "arm64": "aarch64"}[arch]:
        raise GateError(f"RPM version/architecture mismatch: {fields[1:]}")
    inventory = run("rpm", "-qlp", str(package)).splitlines()
    if not any(name.endswith("/bin/pqvpn_node") for name in inventory):
        raise GateError("RPM payload does not contain pqvpn_node")


def check_arch(package, version, arch):
    if arch != "x86_64" or not re.search(r"\.pkg\.tar\.(zst|xz)$", package.name):
        raise GateError("Unsupported Arch release package")
    metadata = run("bsdtar", "-xOf", str(package), ".PKGINFO")
    fields = {}
    for line in metadata.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            fields[key] = value
    expected = version_with_bash("pqvpn_arch_version", version)
    if (fields.get("pkgname") != "pqvpn" or
            fields.get("pkgver") != expected + "-1" or
            fields.get("arch") != "x86_64"):
        raise GateError("Incorrect Arch package name/version/architecture")
    inventory = run("bsdtar", "-tf", str(package)).splitlines()
    if not any(name.lstrip("./").endswith("bin/pqvpn_node") for name in inventory):
        raise GateError("Arch payload does not contain pqvpn_node")


def check_appimage(package, version, arch):
    if package.suffix != ".AppImage" or version not in package.name:
        raise GateError("Expected versioned AppImage candidate")
    with package.open("rb") as source:
        assert_elf(source.read(20), arch)
    if arch != native_arch() or not os.access(package, os.X_OK):
        raise GateError("AppImage extraction requires a native executable runner")
    with tempfile.TemporaryDirectory(prefix="pqvpn-appimage-gate-") as tmp:
        # Type-2 AppImage extraction does not require FUSE; it exercises the
        # actual runtime and reveals the embedded SquashFS payload.
        run(str(package), "--appimage-extract", cwd=tmp, timeout=120)
        root = Path(tmp) / "squashfs-root"
        if not (root / "AppRun").is_file():
            raise GateError("AppImage payload lacks AppRun")
        node = root / "usr/bin/pqvpn_node"
        if not node.is_file():
            raise GateError("AppImage payload lacks usr/bin/pqvpn_node")
        with node.open("rb") as source:
            assert_elf(source.read(20), arch)


def verify(target, package, version):
    assert_version(version)
    kind, arch = LINUX_TARGETS[target]
    package = Path(package).resolve(strict=True)
    if not package.is_file() or package.stat().st_size == 0:
        raise GateError("Missing or empty package")
    handler = {"tar": check_tar, "deb": check_deb, "rpm": check_rpm,
               "arch": check_arch, "appimage": check_appimage}[kind]
    handler(package, version, arch)
    return {"target": target, "package": package.name, "artifact_verified": True,
            "scope": "package format/metadata/architecture only; NOT native VPN qualification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=sorted(LINUX_TARGETS))
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.target, args.package, args.version), indent=2))
    except (GateError, OSError) as exc:
        print(f"Distribution artifact gate FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
