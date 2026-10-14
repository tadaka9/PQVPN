#!/usr/bin/env python3
"""Build and verify the bounded PQVPN release-update container."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile

MAGIC = b"PQVPNPKG1\n"
MAX_MANIFEST = 64 * 1024
MAX_PAYLOAD = 1024 * 1024 * 1024
SAFE_VALUE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")
SAFE_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+~-]*$")
SAFE_TARGET = re.compile(r"^[a-z0-9]+-[a-z0-9_]+$")


def digest(path: Path) -> tuple[str, int]:
    result = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_PAYLOAD:
                raise ValueError("payload exceeds 1 GiB")
            result.update(chunk)
    return result.hexdigest(), size


def validate_manifest(manifest: object) -> dict:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "product", "version", "target", "payload_name",
        "payload_size", "payload_sha256", "install_mode",
    }:
        raise ValueError("invalid manifest fields")
    if manifest["schema"] != 1 or manifest["product"] != "PQVPN":
        raise ValueError("unsupported package schema")
    if not isinstance(manifest["version"], str) or not SAFE_VALUE.fullmatch(manifest["version"]):
        raise ValueError("unsafe version")
    if not isinstance(manifest["target"], str) or not SAFE_TARGET.fullmatch(manifest["target"]):
        raise ValueError("unsafe target")
    name = manifest["payload_name"]
    if not isinstance(name, str) or Path(name).name != name or not SAFE_NAME.fullmatch(name):
        raise ValueError("unsafe payload name")
    if not isinstance(manifest["payload_size"], int) or not 0 < manifest["payload_size"] <= MAX_PAYLOAD:
        raise ValueError("invalid payload size")
    if not isinstance(manifest["payload_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", manifest["payload_sha256"]):
        raise ValueError("invalid payload checksum")
    if manifest["install_mode"] not in {"msi", "deb", "package", "archive"}:
        raise ValueError("invalid install mode")
    return manifest


def install_mode(payload: Path) -> str:
    name = payload.name.lower()
    if name.endswith(".msi"):
        return "msi"
    if name.endswith(".deb"):
        return "deb"
    if name.endswith((".pkg", ".dmg", ".appimage", ".rpm", ".pkg.tar.xz", ".pkg.tar.zst")):
        return "package"
    if name.endswith((".tar.gz", ".zip")):
        return "archive"
    raise ValueError("unsupported native package type")


def build(payload: Path, version: str, target: str, output: Path) -> None:
    if not payload.is_file() or payload.is_symlink():
        raise ValueError("payload must be a regular file")
    checksum, size = digest(payload)
    manifest = validate_manifest({
        "schema": 1,
        "product": "PQVPN",
        "version": version,
        "target": target,
        "payload_name": payload.name,
        "payload_size": size,
        "payload_sha256": checksum,
        "install_mode": install_mode(payload),
    })
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_MANIFEST:
        raise ValueError("manifest is too large")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=output.name + ".", delete=False) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(MAGIC)
            temporary.write(struct.pack(">I", len(encoded)))
            temporary.write(encoded)
            with payload.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    temporary.write(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, output)
    except BaseException:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
        raise


def verify(package: Path, extract: Path | None = None) -> dict:
    with package.open("rb") as source:
        if source.read(len(MAGIC)) != MAGIC:
            raise ValueError("invalid package magic")
        raw_length = source.read(4)
        if len(raw_length) != 4:
            raise ValueError("truncated package header")
        length = struct.unpack(">I", raw_length)[0]
        if not 0 < length <= MAX_MANIFEST:
            raise ValueError("invalid manifest length")
        encoded = source.read(length)
        if len(encoded) != length:
            raise ValueError("truncated manifest")
        manifest = validate_manifest(json.loads(encoded))
        result = hashlib.sha256()
        size = 0
        output = None
        temporary_path = None
        try:
            if extract is not None:
                extract.mkdir(parents=True, exist_ok=True)
                destination = extract / manifest["payload_name"]
                if destination.parent != extract:
                    raise ValueError("payload escapes extraction directory")
                output = tempfile.NamedTemporaryFile(dir=extract, prefix=destination.name + ".", delete=False)
                temporary_path = Path(output.name)
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_PAYLOAD:
                    raise ValueError("payload exceeds 1 GiB")
                result.update(chunk)
                if output:
                    output.write(chunk)
            if size != manifest["payload_size"] or result.hexdigest() != manifest["payload_sha256"]:
                raise ValueError("payload size or checksum mismatch")
            if output:
                output.flush()
                os.fsync(output.fileno())
                output.close()
                output = None
                os.replace(temporary_path, extract / manifest["payload_name"])
        finally:
            if output:
                output.close()
            if temporary_path and temporary_path.exists():
                temporary_path.unlink()
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("build")
    create.add_argument("--payload", type=Path, required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--target", required=True)
    create.add_argument("--output", type=Path, required=True)
    inspect = commands.add_parser("verify")
    inspect.add_argument("package", type=Path)
    inspect.add_argument("--extract", type=Path)
    args = parser.parse_args()
    if args.command == "build":
        build(args.payload, args.version, args.target, args.output)
    else:
        print(json.dumps(verify(args.package, args.extract), sort_keys=True))


if __name__ == "__main__":
    main()
