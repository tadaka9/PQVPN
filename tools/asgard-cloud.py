#!/usr/bin/env python3
"""Asgard Cloud: encrypted, content-addressed multi-peer storage foundation.

Storage roots are local paths (including operator-mounted remote volumes). Data
is encrypted before placement; roots never receive the master key or plaintext.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import secrets
import shutil
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK_BYTES = 4 * 1024 * 1024
CAPABILITY_SCHEMA = 1
RECEIPT_SCHEMA = 1
MAX_CAPABILITY_LIFETIME = 24 * 60 * 60
MAX_CONFIG_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CAPABILITY_BYTES = 64 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_LEDGER_ENTRIES = 100_000
MAX_NODES = 128
MAX_REPLICAS = 8
MAX_OBJECT_BYTES = 1024 * 1024 * 1024 * 1024
DEFAULT_MIN_FREE_BYTES = 64 * 1024 * 1024


def erasure_encode(blob: bytes, data_shards: int) -> list[bytes]:
    """Return k data shards plus one XOR parity shard."""
    if not blob or data_shards < 2 or data_shards > 32:
        raise ValueError("erasure coding requires 2..32 data shards and nonempty data")
    width = (len(blob) + data_shards - 1) // data_shards
    padded = blob + bytes(width * data_shards - len(blob))
    shards = [padded[index * width:(index + 1) * width]
              for index in range(data_shards)]
    parity = bytearray(width)
    for shard in shards:
        for index, value in enumerate(shard):
            parity[index] ^= value
    return shards + [bytes(parity)]


def erasure_reconstruct(shards: list[bytes | None], original_size: int) -> bytes:
    """Reconstruct data when at most one of k+1 shards is unavailable."""
    if len(shards) < 3 or len(shards) > 33 or original_size < 1:
        raise ValueError("invalid erasure shard set")
    present = [shard for shard in shards if shard is not None]
    if not present or any(len(shard) != len(present[0]) for shard in present):
        raise ValueError("erasure shards must have one fixed width")
    missing = [index for index, shard in enumerate(shards) if shard is None]
    if len(missing) > 1:
        raise RuntimeError("XOR erasure set cannot recover more than one missing shard")
    restored = list(shards)
    data_count = len(shards) - 1
    if missing and missing[0] < data_count:
        recovered = bytearray(len(present[0]))
        for shard in present:
            for index, value in enumerate(shard):
                recovered[index] ^= value
        restored[missing[0]] = bytes(recovered)
    if any(restored[index] is None for index in range(data_count)):
        raise RuntimeError("data shard remains unavailable")
    value = b"".join(restored[:data_count])[:original_size]
    if len(value) != original_size:
        raise RuntimeError("reconstructed data is shorter than declared size")
    return value


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def read_json(path: Path, max_bytes: int):
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"refusing oversized JSON input: {path} ({size} bytes)")
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def load_identity(path: Path, create: bool = False) -> Ed25519PrivateKey:
    if not path.exists():
        if not create:
            raise FileNotFoundError(f"identity does not exist: {path}")
        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(serialization.Encoding.Raw,
                                    serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
        atomic_write(path, raw)
        return private
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"identity permissions must be 0600: {path}")
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ValueError("Asgard identity must contain exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_text(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def sign_record(record: dict, private: Ed25519PrivateKey) -> dict:
    unsigned = dict(record)
    unsigned.pop("signature", None)
    signed = dict(unsigned)
    signed["signature"] = base64.b64encode(
        private.sign(canonical_json(unsigned))).decode("ascii")
    return signed


def verify_signed_record(record: dict) -> None:
    if not isinstance(record, dict):
        raise ValueError("signed record must be an object")
    try:
        public_raw = base64.b64decode(record["public_key"], validate=True)
        signature = base64.b64decode(record["signature"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid signed record encoding") from error
    if len(public_raw) != 32 or len(signature) != 64:
        raise ValueError("invalid signed record key or signature length")
    unsigned = dict(record)
    unsigned.pop("signature", None)
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature, canonical_json(unsigned))
    except (InvalidSignature, ValueError) as error:
        raise ValueError("signed record verification failed") from error


def issue_capability(node: str, capacity_bytes: int, max_object_bytes: int,
                     expires_at: int, private: Ed25519PrivateKey,
                     now: int | None = None) -> dict:
    issued_at = int(time.time()) if now is None else int(now)
    if not node or len(node) > 128:
        raise ValueError("capability requires a bounded node name")
    if capacity_bytes < CHUNK_BYTES or max_object_bytes < 1:
        raise ValueError("capability capacity limits are invalid")
    if max_object_bytes > capacity_bytes:
        raise ValueError("maximum object size cannot exceed capacity")
    if expires_at <= issued_at or expires_at - issued_at > MAX_CAPABILITY_LIFETIME:
        raise ValueError("capability expiry must be within 24 hours")
    public_key = public_key_text(private)
    peer_id = hashlib.sha256(base64.b64decode(public_key)).hexdigest()
    return sign_record({
        "schema": CAPABILITY_SCHEMA,
        "kind": "pqvpn-asgard-storage-capability",
        "peer_id": peer_id,
        "node": node,
        "capacity_bytes": capacity_bytes,
        "max_object_bytes": max_object_bytes,
        "chunk_bytes": CHUNK_BYTES,
        "transport": "pqvpn-authenticated-session",
        "issued_at": issued_at,
        "expires_at": int(expires_at),
        "nonce": secrets.token_hex(16),
        "public_key": public_key,
    }, private)


def verify_capability(capability: dict, now: int | None = None) -> None:
    verify_signed_record(capability)
    current = int(time.time()) if now is None else int(now)
    if capability.get("schema") != CAPABILITY_SCHEMA or capability.get("kind") != "pqvpn-asgard-storage-capability":
        raise ValueError("unsupported Asgard capability")
    if capability.get("transport") != "pqvpn-authenticated-session":
        raise ValueError("capability requires the authenticated PQVPN transport")
    public_raw = base64.b64decode(capability["public_key"], validate=True)
    if capability.get("peer_id") != hashlib.sha256(public_raw).hexdigest():
        raise ValueError("capability peer id does not match its public key")
    issued = capability.get("issued_at")
    expires = capability.get("expires_at")
    if not isinstance(issued, int) or not isinstance(expires, int) or issued > current + 300:
        raise ValueError("capability timestamp is invalid")
    if expires <= current or expires - issued > MAX_CAPABILITY_LIFETIME:
        raise ValueError("capability is expired or exceeds its lifetime bound")
    capacity = capability.get("capacity_bytes")
    maximum = capability.get("max_object_bytes")
    if (not isinstance(capacity, int) or not isinstance(maximum, int) or
            capacity < CHUNK_BYTES or maximum < 1 or maximum > capacity):
        raise ValueError("capability capacity limits are invalid")


def record_digest(record: dict) -> str:
    return hashlib.sha256(canonical_json(record)).hexdigest()


def manifest_commitment(manifest: dict) -> str:
    if manifest.get("schema") != 1 or not isinstance(manifest.get("size"), int):
        raise ValueError("invalid manifest for receipt")
    if not isinstance(manifest.get("chunks"), list) or not manifest["chunks"]:
        raise ValueError("invalid manifest for receipt")
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def append_receipt(ledger: list[dict], capability: dict, manifest: dict,
                   private: Ed25519PrivateKey, now: int | None = None) -> dict:
    current = int(time.time()) if now is None else int(now)
    if not isinstance(ledger, list) or len(ledger) >= MAX_LEDGER_ENTRIES:
        raise ValueError("Asgard receipt ledger is full")
    verify_capability(capability, current)
    if public_key_text(private) != capability["public_key"]:
        raise ValueError("receipt identity does not own the capability")
    if manifest["size"] > capability["max_object_bytes"]:
        raise ValueError("object exceeds advertised capability")
    previous = record_digest(ledger[-1]) if ledger else "0" * 64
    receipt = sign_record({
        "schema": RECEIPT_SCHEMA,
        "kind": "pqvpn-asgard-storage-receipt",
        "sequence": len(ledger),
        "previous": previous,
        "capability": record_digest(capability),
        "manifest": manifest_commitment(manifest),
        "bytes": manifest["size"],
        "recorded_at": current,
        "public_key": capability["public_key"],
    }, private)
    ledger.append(receipt)
    return receipt


def verify_receipt_ledger(ledger: list[dict], now: int | None = None) -> None:
    if not isinstance(ledger, list) or len(ledger) > MAX_LEDGER_ENTRIES:
        raise ValueError("Asgard receipt ledger exceeds its entry bound")
    current = int(time.time()) if now is None else int(now)
    previous = "0" * 64
    previous_time = 0
    for sequence, receipt in enumerate(ledger):
        verify_signed_record(receipt)
        if (receipt.get("schema") != RECEIPT_SCHEMA or
                receipt.get("kind") != "pqvpn-asgard-storage-receipt" or
                receipt.get("sequence") != sequence or
                receipt.get("previous") != previous):
            raise ValueError("invalid Asgard receipt chain")
        if not isinstance(receipt.get("bytes"), int) or receipt["bytes"] < 1:
            raise ValueError("invalid Asgard receipt size")
        recorded_at = receipt.get("recorded_at")
        if (not isinstance(recorded_at, int) or recorded_at < previous_time or
                recorded_at > current + 300):
            raise ValueError("invalid Asgard receipt timestamp")
        for field in ("capability", "manifest"):
            value = receipt.get(field)
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError("invalid Asgard receipt commitment")
            try:
                bytes.fromhex(value)
            except ValueError as error:
                raise ValueError("invalid Asgard receipt commitment") from error
        previous = record_digest(receipt)
        previous_time = recorded_at


def validate_config(config: dict) -> None:
    if not isinstance(config, dict):
        raise ValueError("configuration must be an object")
    nodes = config.get("nodes")
    if not isinstance(nodes, list) or not nodes or len(nodes) > MAX_NODES:
        raise ValueError("configuration requires at least one storage peer")
    replicas = config.get("replicas", 2)
    if (not isinstance(replicas, int) or isinstance(replicas, bool) or
            replicas < 1 or replicas > MAX_REPLICAS):
        raise ValueError("replicas must be an integer between 1 and 8")
    names = []
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("name"), str):
            raise ValueError("every storage peer requires a string name")
        if (not node["name"] or len(node["name"]) > 128 or
                not isinstance(node.get("root"), str) or not node["root"] or
                len(node["root"]) > 4096):
            raise ValueError("every storage peer requires a nonempty name and root")
        domain = node.get("failure_domain", node["name"])
        if not isinstance(domain, str) or not domain or len(domain) > 128:
            raise ValueError("storage peer failure_domain must be a bounded string")
        if not isinstance(node.get("enabled", True), bool):
            raise ValueError("storage peer enabled flag must be boolean")
        minimum_free = node.get("min_free_bytes", DEFAULT_MIN_FREE_BYTES)
        if (not isinstance(minimum_free, int) or isinstance(minimum_free, bool) or
                minimum_free < 0 or minimum_free > MAX_OBJECT_BYTES):
            raise ValueError("storage peer min_free_bytes is invalid")
        latency = node.get("latency_ms", 1000)
        capacity = node.get("capacity_bps", 1)
        availability = node.get("availability_ppm", 900_000)
        if (not isinstance(latency, int) or isinstance(latency, bool) or latency < 1 or latency > 60_000 or
                not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1 or
                not isinstance(availability, int) or isinstance(availability, bool) or
                availability < 900_000 or availability > 1_000_000):
            raise ValueError("storage peer retrieval metrics are invalid")
        names.append(node["name"])
    if len(names) != len(set(names)):
        raise ValueError("storage peer names must be unique")
    enabled_domains = {
        node.get("failure_domain", node["name"])
        for node in nodes if node.get("enabled", True)
    }
    if len(enabled_domains) < replicas:
        raise ValueError("configuration lacks independent failure domains for quorum")


def validate_manifest(manifest: dict, config: dict) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    if manifest.get("schema") != 1:
        raise ValueError("unsupported Asgard manifest schema")
    try:
        object_id = bytes.fromhex(manifest["object_id"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid Asgard object id") from error
    if len(object_id) != 16:
        raise ValueError("invalid Asgard object id")
    replicas = manifest.get("replicas", config.get("replicas", 2))
    if (not isinstance(replicas, int) or isinstance(replicas, bool) or
            replicas < 1 or replicas > MAX_REPLICAS):
        raise ValueError("invalid manifest replica target")
    chunks = manifest.get("chunks")
    if (not isinstance(chunks, list) or not chunks or
            len(chunks) > (MAX_OBJECT_BYTES + CHUNK_BYTES - 1) // CHUNK_BYTES):
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
                len(placements) > MAX_REPLICAS or
                len(placements) != len(set(placements)) or
                any(name not in known_nodes for name in placements)):
            raise ValueError("invalid manifest storage placement")
        total += size
    if total > MAX_OBJECT_BYTES or manifest.get("size") != total:
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
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"master key permissions must be 0600: {path}")
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Asgard master key must contain exactly 32 bytes")
    return key


def chunk_key(master: bytes, object_id: bytes, index: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=object_id,
                info=b"pqvpn-asgard-v1/chunk/" + index.to_bytes(8, "big")).derive(master)


def rank_nodes(nodes: list[dict], chunk_id: str) -> list[dict]:
    enabled = [node for node in nodes if node.get("enabled", True)]
    return sorted(enabled, key=lambda node: hashlib.sha256(
        f"{chunk_id}\0{node['name']}".encode()).digest(), reverse=True)


def select_nodes(nodes: list[dict], chunk_id: str, replicas: int) -> list[dict]:
    enabled = rank_nodes(nodes, chunk_id)
    if replicas < 1 or len(enabled) < replicas:
        raise RuntimeError("insufficient enabled storage peers for replication quorum")
    selected = []
    domains = set()
    for node in enabled:
        domain = node.get("failure_domain", node["name"])
        if domain in domains:
            continue
        selected.append(node)
        domains.add(domain)
        if len(selected) == replicas:
            return selected
    raise RuntimeError("insufficient independent failure domains for replication quorum")


def store_blob(node: dict, chunk_id: str, blob: bytes) -> str:
    root = Path(node["root"]).expanduser().resolve()
    if not root.is_dir():
        raise OSError(f"storage root unavailable on {node['name']}")
    destination = root / "chunks" / chunk_id[:2] / chunk_id
    if destination.exists():
        if hashlib.sha256(destination.read_bytes()).hexdigest() != chunk_id:
            raise RuntimeError(f"corrupt existing chunk on {node['name']}")
    else:
        minimum_free = node.get("min_free_bytes", DEFAULT_MIN_FREE_BYTES)
        if shutil.disk_usage(root).free < len(blob) + minimum_free:
            raise OSError(f"storage reserve reached on {node['name']}")
        atomic_write(destination, blob)
    return node["name"]


def put(source: Path, config: dict, key: bytes) -> dict:
    validate_config(config)
    nodes = config["nodes"]
    replicas = int(config.get("replicas", 2))
    source_size = source.stat().st_size
    if source_size < 1 or source_size > MAX_OBJECT_BYTES:
        raise ValueError("object size is outside the supported bound")
    object_id = secrets.token_bytes(16)
    chunks = []
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
            for future in futures:
                future.result()
            chunks.append({"index": index, "id": chunk_id, "size": len(plaintext),
                           "nodes": [node["name"] for node in selected]})
            index += 1
    if not chunks:
        raise ValueError("refusing to store an empty object")
    return {"schema": 1, "object_id": object_id.hex(), "size": source_size,
            "chunk_bytes": CHUNK_BYTES, "replicas": replicas, "chunks": chunks}


def locate_blob(config: dict, chunk: dict) -> bytes:
    by_name = {node["name"]: node for node in config["nodes"]}
    candidates=sorted(chunk["nodes"],key=lambda name:(
        -by_name[name].get("capacity_bps",1)*by_name[name].get("availability_ppm",900_000)/
        (by_name[name].get("latency_ms",1000)+1),name))
    for name in candidates:
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


def blob_path(node: dict, chunk_id: str) -> Path:
    return Path(node["root"]).expanduser().resolve() / "chunks" / chunk_id[:2] / chunk_id


def replica_audit(manifest: dict, config: dict) -> dict:
    validate_config(config)
    validate_manifest(manifest, config)
    by_name = {node["name"]: node for node in config["nodes"]}
    desired = int(manifest.get("replicas", config.get("replicas", 2)))
    chunks = []
    for chunk in manifest["chunks"]:
        healthy = []
        domains = set()
        for name in chunk["nodes"]:
            node = by_name[name]
            try:
                blob = blob_path(node, chunk["id"]).read_bytes()
            except OSError:
                continue
            if hashlib.sha256(blob).hexdigest() != chunk["id"]:
                continue
            healthy.append(name)
            domains.add(node.get("failure_domain", node["name"]))
        chunks.append({"index": chunk["index"], "healthy": healthy,
                       "healthy_replicas": len(healthy),
                       "independent_domains": len(domains),
                       "desired_replicas": desired,
                       "state": "healthy" if len(domains) >= desired else
                                "degraded" if healthy else "unavailable"})
    return {"schema": 1, "object_id": manifest["object_id"],
            "state": "unavailable" if any(c["state"] == "unavailable" for c in chunks) else
                     "degraded" if any(c["state"] == "degraded" for c in chunks) else "healthy",
            "chunks": chunks}


def repair_replicas(manifest: dict, config: dict) -> dict:
    validate_config(config)
    validate_manifest(manifest, config)
    desired = int(manifest.get("replicas", config.get("replicas", 2)))
    if desired < 1:
        raise ValueError("invalid replica target")
    nodes = config["nodes"]
    by_name = {node["name"]: node for node in nodes}
    repaired = json.loads(json.dumps(manifest))
    for chunk in repaired["chunks"]:
        candidates = list(chunk["nodes"]) + [
            node["name"] for node in nodes if node["name"] not in chunk["nodes"]]
        blob = None
        for name in candidates:
            node = by_name[name]
            try:
                candidate = blob_path(node, chunk["id"]).read_bytes()
            except OSError:
                continue
            if hashlib.sha256(candidate).hexdigest() == chunk["id"]:
                blob = candidate
                break
        if blob is None:
            raise RuntimeError(f"no valid replica for chunk {chunk['index']}")

        placements = []
        domains = set()
        for node in rank_nodes(nodes, chunk["id"]):
            domain = node.get("failure_domain", node["name"])
            if domain in domains:
                continue
            try:
                store_blob(node, chunk["id"], blob)
            except OSError:
                continue
            placements.append(node["name"])
            domains.add(domain)
            if len(placements) == desired:
                break
        if len(placements) < desired:
            raise RuntimeError(
                f"could not restore replication quorum for chunk {chunk['index']}")
        chunk["nodes"] = placements
    return repaired


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
    parser.add_argument("--config", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--identity", type=Path,
                        help="separate Ed25519 identity for capabilities and receipts")
    sub = parser.add_subparsers(dest="command", required=True)
    put_parser = sub.add_parser("put")
    put_parser.add_argument("source", type=Path)
    put_parser.add_argument("manifest", type=Path)
    get_parser = sub.add_parser("get")
    get_parser.add_argument("manifest", type=Path)
    get_parser.add_argument("destination", type=Path)
    capability_parser = sub.add_parser("capability-issue")
    capability_parser.add_argument("output", type=Path)
    capability_parser.add_argument("--node", required=True)
    capability_parser.add_argument("--capacity-bytes", required=True, type=int)
    capability_parser.add_argument("--max-object-bytes", required=True, type=int)
    capability_parser.add_argument("--expires-hours", type=int, default=24)
    capability_verify = sub.add_parser("capability-verify")
    capability_verify.add_argument("capability", type=Path)
    receipt_append = sub.add_parser("receipt-append")
    receipt_append.add_argument("capability", type=Path)
    receipt_append.add_argument("manifest", type=Path)
    receipt_append.add_argument("ledger", type=Path)
    receipt_verify = sub.add_parser("receipt-verify")
    receipt_verify.add_argument("ledger", type=Path)
    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("manifest", type=Path)
    repair_parser = sub.add_parser("repair")
    repair_parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    if args.command == "put":
        if args.config is None or args.key is None:
            parser.error("put requires --config and --key")
        config = read_json(args.config, MAX_CONFIG_BYTES)
        manifest = put(args.source, config, load_key(args.key, create=True))
        atomic_write(args.manifest, (json.dumps(manifest, indent=2) + "\n").encode())
        print(f"stored {manifest['size']} bytes in {len(manifest['chunks'])} encrypted chunks")
    elif args.command == "get":
        if args.config is None or args.key is None:
            parser.error("get requires --config and --key")
        config = read_json(args.config, MAX_CONFIG_BYTES)
        manifest = read_json(args.manifest, MAX_MANIFEST_BYTES)
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        get(manifest, args.destination, config, load_key(args.key))
        print(f"restored {manifest['size']} bytes to {args.destination}")
    elif args.command == "capability-issue":
        if args.identity is None:
            parser.error("capability-issue requires --identity")
        now = int(time.time())
        capability = issue_capability(
            args.node, args.capacity_bytes, args.max_object_bytes,
            now + args.expires_hours * 60 * 60,
            load_identity(args.identity, create=True), now)
        atomic_write(args.output, (json.dumps(capability, indent=2) + "\n").encode())
        print(f"issued capability {record_digest(capability)} expiring at {capability['expires_at']}")
    elif args.command == "capability-verify":
        capability = read_json(args.capability, MAX_CAPABILITY_BYTES)
        verify_capability(capability)
        print(f"valid capability {record_digest(capability)}")
    elif args.command == "receipt-append":
        if args.identity is None:
            parser.error("receipt-append requires --identity")
        capability = read_json(args.capability, MAX_CAPABILITY_BYTES)
        manifest = read_json(args.manifest, MAX_MANIFEST_BYTES)
        ledger = []
        if args.ledger.exists():
            ledger = read_json(args.ledger, MAX_LEDGER_BYTES)
            if not isinstance(ledger, list):
                raise ValueError("Asgard receipt ledger must be an array")
            verify_receipt_ledger(ledger)
        receipt = append_receipt(ledger, capability, manifest,
                                 load_identity(args.identity))
        atomic_write(args.ledger, (json.dumps(ledger, indent=2) + "\n").encode())
        print(f"appended receipt {record_digest(receipt)} at sequence {receipt['sequence']}")
    elif args.command == "receipt-verify":
        ledger = read_json(args.ledger, MAX_LEDGER_BYTES)
        if not isinstance(ledger, list):
            raise ValueError("Asgard receipt ledger must be an array")
        verify_receipt_ledger(ledger)
        head = record_digest(ledger[-1]) if ledger else "0" * 64
        print(f"valid receipt chain length={len(ledger)} head={head}")
    elif args.command == "audit":
        if args.config is None:
            parser.error("audit requires --config")
        config = read_json(args.config, MAX_CONFIG_BYTES)
        manifest = read_json(args.manifest, MAX_MANIFEST_BYTES)
        report = replica_audit(manifest, config)
        print(json.dumps(report, sort_keys=True))
        if report["state"] != "healthy":
            return 2
    else:
        if args.config is None:
            parser.error("repair requires --config")
        config = read_json(args.config, MAX_CONFIG_BYTES)
        manifest = read_json(args.manifest, MAX_MANIFEST_BYTES)
        repaired = repair_replicas(manifest, config)
        atomic_write(args.manifest, (json.dumps(repaired, indent=2) + "\n").encode())
        report = replica_audit(repaired, config)
        if report["state"] != "healthy":
            raise RuntimeError("repair completed without a healthy independent quorum")
        print(f"repaired {len(repaired['chunks'])} chunks to independent quorum")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
