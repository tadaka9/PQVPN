#!/usr/bin/env python3
"""Native package *artifact* gate, not a privileged VPN release qualification.

This verifies real bytes/metadata produced for Linux distributions. A PASS here
does not satisfy tunnel, install/upgrade/rollback, signature or provenance gates.
"""
import argparse
import hashlib
import json
import posixpath
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import struct
import tarfile

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
MAX_NODE = 128 * 1024 * 1024
MAX_PACKAGE = 1024 * 1024 * 1024


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


def assert_elf(data, arch, *, container_size=None):
    """Reject truncated/inert ELF64, not merely a valid 20-byte identification."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] not in (1, 2):
        raise GateError("Missing, truncated, or unsupported ELF64 binary")
    byteorder = "little" if data[5] == 1 else "big"
    unpack = "<" if byteorder == "little" else ">"
    machine = int.from_bytes(data[18:20], byteorder)
    if machine != ELF_MACHINE[arch]:
        raise GateError(f"Wrong ELF architecture: {machine}; expected {arch}")
    elf_type = struct.unpack_from(unpack + "H", data, 16)[0]
    entry, phoff = struct.unpack_from(unpack + "QQ", data, 24)
    ehsize, phentsize, phnum = struct.unpack_from(unpack + "HHH", data, 52)
    full_size = container_size if container_size is not None else len(data)
    if (elf_type not in (2, 3) or ehsize != 64 or phentsize < 56 or
            not 1 <= phnum <= 128 or phoff < 64 or
            phoff + phnum * phentsize > len(data)):
        raise GateError("Incomplete or invalid ELF program headers")
    executable_load = False
    entry_mapped = False
    for index in range(phnum):
        typ, flags, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from(
            unpack + "IIQQQQQQ", data, phoff + index * phentsize)
        if typ == 1:
            if filesz > memsz or offset + filesz > full_size:
                raise GateError("Truncated ELF load segment")
            if flags & 1 and filesz:
                executable_load = True
                if vaddr <= entry < vaddr + memsz:
                    entry_mapped = True
    if not executable_load or not entry_mapped:
        raise GateError("ELF lacks a mapped executable entry point")


def safe_member_name(name, *, root=None):
    if (not name or name.startswith("/") or "\\" in name or
            "\x00" in name or ".." in name.split("/")):
        raise GateError(f"Unsafe archive entry: {name}")
    normalized = posixpath.normpath(name)
    if normalized in (".", "..") or normalized.startswith("../"):
        raise GateError(f"Unsafe archive entry: {name}")
    if root is not None and normalized != root and not normalized.startswith(root + "/"):
        raise GateError(f"Unexpected archive root: {name}")
    return normalized


def safe_link(member, name):
    target = member.linkname
    if not target or target.startswith("/") or "\\" in target:
        raise GateError(f"Unsafe archive symlink: {name}")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    if resolved in (".", "..") or resolved.startswith("../"):
        raise GateError(f"Unsafe archive symlink: {name}")
    return resolved


def binary_bytes(stream, size):
    if size < 120 or size > MAX_NODE:
        raise GateError("Packaged node size is implausible or excessive")
    data = stream.read(size + 1)
    if len(data) != size:
        raise GateError("Truncated packaged node")
    return data


def verify_known_binary(data, known_binary, version):
    # Only compare with a binary already built and smoke-tested locally.
    # The archive itself is NEVER launched by the verifier.
    if known_binary is None:
        return
    known = Path(known_binary)
    if not known.is_file() or known.stat().st_size > MAX_NODE:
        raise GateError("Trusted local node is missing or too large")
    if hashlib.sha256(data).digest() != hashlib.sha256(known.read_bytes()).digest():
        raise GateError("Packaged node differs from trusted native build")

def assert_version(version):
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", version):
        raise GateError("Unsafe release version")


def version_with_bash(function, version):
    if function not in {"pqvpn_debian_version", "pqvpn_arch_version"}:
        raise GateError("Unexpected version conversion")
    script = ROOT / "packaging/version-functions.sh"
    return run("bash", "-c", 'source "$1"; "$2" "$3"', "bash",
               str(script), function, version)


def check_tar(package, version, arch, *, target=None, trusted_node=None):
    target = target or ("linux-" + arch)
    stage = f"PQVPN-{version}-{target}"
    if package.name != stage + ".tar.gz":
        raise GateError("Expected exact target-specific versioned tar.gz archive")
    node_name = stage + "/bin/pqvpn_node"
    try:
        with tarfile.open(package, "r:gz") as archive:
            seen = set()
            node = None
            for item in archive:
                name = safe_member_name(item.name, root=stage)
                if name in seen:
                    raise GateError(f"Duplicate archive entry: {name}")
                seen.add(name)
                if item.issym():
                    resolved = safe_link(item, name)
                    if resolved != stage and not resolved.startswith(stage + "/"):
                        raise GateError(f"Unsafe archive symlink: {name}")
                if item.islnk() or item.isdev() or item.isfifo():
                    raise GateError(f"Unexpected archive entry type: {name}")
                if name == node_name:
                    if not item.isfile() or not item.mode & 0o111:
                        raise GateError("Packaged pqvpn_node is not an executable regular file")
                    stream = archive.extractfile(item)
                    if stream is None:
                        raise GateError("Cannot read packaged pqvpn_node")
                    node = binary_bytes(stream, item.size)
                    assert_elf(node, arch)
            if node is None:
                raise GateError("Expected exactly one packaged pqvpn_node at the correct stage path")
            verify_known_binary(node, trusted_node, version)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise GateError(f"Unusable tar archive: {exc}") from exc

def check_deb(package, version, arch, *, target=None, trusted_node=None):
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
    # Stream the DEB filesystem archive and inspect members in memory. Never
    # call dpkg-deb -x on untrusted input and never follow archive symlinks.
    process = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(package)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    seen = set()
    node = None
    config = False
    launcher = False
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for item in archive:
                if item.name in (".", "./"):
                    continue
                name = safe_member_name(item.name)
                if name in seen:
                    raise GateError(f"Duplicate Debian archive entry: {name}")
                seen.add(name)
                if item.isdev() or item.isfifo() or item.islnk():
                    raise GateError(f"Disallowed Debian archive entry type: {name}")
                if item.issym():
                    resolved = safe_link(item, name)
                    if name == "usr/bin/pqvpn_node":
                        launcher = resolved == "usr/lib/pqvpn/bin/pqvpn_node"
                if name == "etc/pqvpn/config.json.example":
                    config = item.isfile() and item.size > 0
                if name == "usr/lib/pqvpn/bin/pqvpn_node":
                    if not item.isfile() or not item.mode & 0o111:
                        raise GateError("Debian node is not executable")
                    stream = archive.extractfile(item)
                    if stream is None:
                        raise GateError("Cannot read packaged Debian node")
                    node = binary_bytes(stream, item.size)
                    assert_elf(node, arch)
        if process.wait(timeout=60):
            raise GateError("dpkg-deb failed to stream package contents")
        if node is None or not launcher or not config:
            raise GateError("Debian package lacks node, safe launcher, or operator configuration")
        verify_known_binary(node, trusted_node, version)
    except (tarfile.TarError, EOFError, OSError, subprocess.TimeoutExpired):
        raise GateError("Debian package has an unreadable or unsafe filesystem archive")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()

def check_rpm(package, version, arch):
    if package.suffix != ".rpm":
        raise GateError("Expected RPM archive")
    raw = run("rpm", "-qp", "--queryformat",
              r"%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n", str(package))
    fields = raw.splitlines()
    if len(fields) != 4 or fields[0] != "pqvpn":
        raise GateError("Invalid RPM name or metadata")
    prerelease = re.fullmatch(
        r"(\d+)\.(\d+)-(alpha|beta)-(\d+)-([0-9A-Za-z.-]+)", version)
    legacy = re.fullmatch(
        r"alpha-(\d+)\.(\d+)-(\d+)-([0-9A-Za-z.-]+)", version)
    if prerelease:
        major, minor, stage, date, label = prerelease.groups()
        numeric = f"{major}.{minor}.0"
        release = f"0.{stage}.{date}.{label.replace('-', '.')}"
    elif legacy:
        major, minor, date, label = legacy.groups()
        numeric = f"{major}.{minor}.0"
        release = f"0.alpha.{date}.{label.replace('-', '.')}"
    else:
        stable = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
        if not stable:
            raise GateError("Unsupported RPM source version")
        numeric = ".".join(stable.groups())
        release = "1"
    if (fields[1] != numeric or fields[2] != release or
            fields[3] != {"x86_64": "x86_64", "arm64": "aarch64"}[arch]):
        raise GateError(f"RPM version/release/architecture mismatch: {fields[1:]}")
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


def run_binary_limited(*args):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        payload = process.stdout.read(MAX_NODE + 1)
        if len(payload) > MAX_NODE:
            raise GateError("Embedded AppImage node exceeds resource limit")
        if process.wait(timeout=60):
            raise GateError("Unable to inspect embedded AppImage node")
        return payload
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def find_squashfs_offset(package):
    # AppImage type 2 contains an appended SquashFS filesystem; scan for a
    # bounded, structurally valid superblock without running its ELF runtime.
    total = package.stat().st_size
    with package.open("rb") as f:
        carry = b""
        position = 0
        while chunk := f.read(1024 * 1024):
            haystack = carry + chunk
            offset = 0
            while (idx := haystack.find(b"hsqs", offset)) != -1:
                absolute = position - len(carry) + idx
                if absolute + 96 <= total and idx + 48 <= len(haystack):
                    major, minor = struct.unpack_from("<HH", haystack, idx + 28)
                    bytes_used = struct.unpack_from("<Q", haystack, idx + 40)[0]
                    if (major, minor) == (4, 0) and 96 <= bytes_used <= total - absolute:
                        return absolute
                offset = idx + 1
            position += len(chunk)
            carry = haystack[-95:]
    raise GateError("AppImage lacks a valid embedded SquashFS superblock")


def check_appimage(package, version, arch, *, target=None, trusted_node=None):
    target = target or ("appimage-" + arch)
    if package.name != f"PQVPN-{version}-{target}.AppImage":
        raise GateError("Expected exact target-specific AppImage candidate")
    # Read the ELF header and program-header table, not its executable code.
    with package.open("rb") as source:
        assert_elf(source.read(1024 * 1024), arch, container_size=package.stat().st_size)
    offset = find_squashfs_offset(package)
    # unsquashfs -l/-cat read the embedded filesystem. We never invoke the
    # unverified AppImage runtime, use FUSE, or extract filesystem paths.
    listing = run("unsquashfs", "-l", "-o", str(offset), str(package), timeout=120)
    entries = set(listing.splitlines())
    if not {"squashfs-root/AppRun", "squashfs-root/usr/bin/pqvpn_node"} <= entries:
        raise GateError("AppImage lacks AppRun or usr/bin/pqvpn_node")
    node = run_binary_limited("unsquashfs", "-cat", "-o", str(offset),
                              str(package), "usr/bin/pqvpn_node")
    assert_elf(node, arch)
    verify_known_binary(node, trusted_node, version)

def verify(target, package, version, *, trusted_node=None):
    assert_version(version)
    kind, arch = LINUX_TARGETS[target]
    package = Path(package).resolve(strict=True)
    if not package.is_file() or not 0 < package.stat().st_size <= MAX_PACKAGE:
        raise GateError("Missing, empty, or excessive package")
    handler = {"tar": check_tar, "deb": check_deb, "rpm": check_rpm,
               "arch": check_arch, "appimage": check_appimage}[kind]
    handler(package, version, arch, target=target, trusted_node=trusted_node)
    return {"target": target, "package": package.name, "artifact_verified": True,
            "scope": "package format/metadata/architecture only; NOT native VPN qualification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=sorted(LINUX_TARGETS))
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--trusted-node", type=Path,
                        help="Previously smoke-tested local node used for a byte-for-byte match")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.target, args.package, args.version, trusted_node=args.trusted_node), indent=2))
    except (GateError, OSError) as exc:
        print(f"Distribution artifact gate FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
