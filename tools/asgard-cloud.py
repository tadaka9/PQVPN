#!/usr/bin/env python3
"""Asgard Cloud: encrypted, content-addressed multi-peer storage foundation.

Storage roots are local paths (including operator-mounted remote volumes). Data
is encrypted before placement; roots never receive the master key or plaintext.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK_BYTES = 4 * 1024 * 1024


def validate_config(config: dict) -> None:
    nodes = config.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("configuration requires at least one storage peer")
    names = []
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("name"), str):
            raise ValueError("every storage peer requires a string name")
        if not node["name"] or not isinstance(node.get("root"), str) or not node["root"]:
            raise ValueError("every storage peer requires a nonempty name and root")
        names.append(node["name"])
    if len(names) != len(set(names)):
        raise ValueError("storage peer names must be unique")


def validate_manifest(manifest: dict, config: dict) -> None:
    if manifest.get("schema") != 1:
        raise ValueError("unsupported Asgard manifest schema")
    try:
        object_id = bytes.fromhex(manifest["object_id"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid Asgard object id") from error
    if len(object_id) != 16:
        raise ValueError("invalid Asgard object id")
    chunks = manifest.get("chunks")
    if not isinstance(chunks, list) or not chunks:
        raise ValueError("manifest requires at least one chunk")
    known_nodes = {node["name"] for node in config["nodes"]}
    total = 0
    for expected, chunk in enumerate(chunks):
        if not isinstance(chunk, dict) or chunk.get("index") != expected:
            raise ValueError("manifest chunk indices must be unique and contiguous")
        chunk_id = chunk.get("id")
        if not isinstance(chunk_id, str) or len(chunk_id) != 64:
            raise ValueError("invalid manifest chunk id")
        try:
            bytes.fromhex(chunk_id)
        except ValueError as error:
            raise ValueError("invalid manifest chunk id") from error
        size = chunk.get("size")
        if not isinstance(size, int) or size < 1 or size > CHUNK_BYTES:
            raise ValueError("invalid manifest chunk size")
        placements = chunk.get("nodes")
        if (not isinstance(placements, list) or not placements or
                len(placements) != len(set(placements)) or
                any(name not in known_nodes for name in placements)):
            raise ValueError("invalid manifest storage placement")
        total += size
    if manifest.get("size") != total:
        raise ValueError("manifest object size does not match its chunks")


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_key(path: Path, create: bool = False) -> bytes:
    if not path.exists():
        if not create:
            raise FileNotFoundError(f"key does not exist: {path}")
        atomic_write(path, secrets.token_bytes(32))
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Asgard master key must contain exactly 32 bytes")
    return key


def chunk_key(master: bytes, object_id: bytes, index: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=object_id,
                info=b"pqvpn-asgard-v1/chunk/" + index.to_bytes(8, "big")).derive(master)


def select_nodes(nodes: list[dict], chunk_id: str, replicas: int) -> list[dict]:
    enabled = [node for node in nodes if node.get("enabled", True)]
    if replicas < 1 or len(enabled) < replicas:
        raise RuntimeError("insufficient enabled storage peers for replication quorum")
    ranked = sorted(enabled, key=lambda node: hashlib.sha256(
        f"{chunk_id}\0{node['name']}".encode()).digest(), reverse=True)
    return ranked[:replicas]


def store_blob(node: dict, chunk_id: str, blob: bytes) -> str:
    root = Path(node["root"]).expanduser().resolve()
    destination = root / "chunks" / chunk_id[:2] / chunk_id
    if destination.exists():
        if hashlib.sha256(destination.read_bytes()).hexdigest() != chunk_id:
            raise RuntimeError(f"corrupt existing chunk on {node['name']}")
    else:
        atomic_write(destination, blob)
    return node["name"]


def put(source: Path, config: dict, key: bytes) -> dict:
    validate_config(config)
    nodes = config["nodes"]
    replicas = int(config.get("replicas", 2))
    object_id = secrets.token_bytes(16)
    chunks = []
    jobs = []
    with source.open("rb") as stream, concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, min(8, len(nodes) * 2))) as pool:
        index = 0
        while plaintext := stream.read(CHUNK_BYTES):
            nonce = secrets.token_bytes(12)
            aad = b"PQVPN-ASGARD-V1" + object_id + index.to_bytes(8, "big")
            ciphertext = AESGCM(chunk_key(key, object_id, index)).encrypt(nonce, plaintext, aad)
            blob = nonce + ciphertext
            chunk_id = hashlib.sha256(blob).hexdigest()
            selected = select_nodes(nodes, chunk_id, replicas)
            futures = [pool.submit(store_blob, node, chunk_id, blob) for node in selected]
            jobs.append((index, chunk_id, len(plaintext), [node["name"] for node in selected], futures))
            index += 1
        for index, chunk_id, size, placements, futures in jobs:
            for future in futures:
                future.result()
            chunks.append({"index": index, "id": chunk_id, "size": size, "nodes": placements})
    if not chunks:
        raise ValueError("refusing to store an empty object")
    return {"schema": 1, "object_id": object_id.hex(), "size": source.stat().st_size,
            "chunk_bytes": CHUNK_BYTES, "replicas": replicas, "chunks": chunks}


def locate_blob(config: dict, chunk: dict) -> bytes:
    by_name = {node["name"]: node for node in config["nodes"]}
    for name in chunk["nodes"]:
        node = by_name.get(name)
        if not node:
            continue
        path = Path(node["root"]).expanduser().resolve() / "chunks" / chunk["id"][:2] / chunk["id"]
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        if hashlib.sha256(blob).hexdigest() == chunk["id"]:
            return blob
    raise RuntimeError(f"no valid replica for chunk {chunk['index']}")


def get(manifest: dict, destination: Path, config: dict, key: bytes) -> None:
    validate_config(config)
    validate_manifest(manifest, config)
    object_id = bytes.fromhex(manifest["object_id"])
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            for chunk in sorted(manifest["chunks"], key=lambda item: item["index"]):
                blob = locate_blob(config, chunk)
                nonce, ciphertext = blob[:12], blob[12:]
                index = int(chunk["index"])
                aad = b"PQVPN-ASGARD-V1" + object_id + index.to_bytes(8, "big")
                plaintext = AESGCM(chunk_key(key, object_id, index)).decrypt(nonce, ciphertext, aad)
                if len(plaintext) != chunk["size"]:
                    raise RuntimeError(f"invalid plaintext length for chunk {index}")
                stream.write(plaintext)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    put_parser = sub.add_parser("put")
    put_parser.add_argument("source", type=Path)
    put_parser.add_argument("manifest", type=Path)
    get_parser = sub.add_parser("get")
    get_parser.add_argument("manifest", type=Path)
    get_parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    if args.command == "put":
        manifest = put(args.source, config, load_key(args.key, create=True))
        atomic_write(args.manifest, (json.dumps(manifest, indent=2) + "\n").encode())
        print(f"stored {manifest['size']} bytes in {len(manifest['chunks'])} encrypted chunks")
    else:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        get(manifest, args.destination, config, load_key(args.key))
        print(f"restored {manifest['size']} bytes to {args.destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
