#!/usr/bin/env python3
# Script per estrarre HELLO dai log, ricostruire il JSON canonico e verificare firme Ed25519
# Produce report JSON e CSV

import argparse
import json
import os
import re
import csv
import base64
from typing import List, Dict, Any, Optional, Tuple

# try importing cryptography
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.backends import default_backend

    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
JSON_FIELD_RE = re.compile(
    r"\{[^}]*\"(ed25519_pk|ed25519_sig|hello_canonical)\"[^}]*\}", re.S
)
RAW_HELLO_RE = re.compile(r"DEBUG\s*-\s*DEBUG raw hello payload: (\{.*?\})(?=\n)", re.S)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def find_json_objects(text: str) -> List[Tuple[int, int, str]]:
    # First try explicit 'raw hello payload' logs
    objs = []
    for m in RAW_HELLO_RE.finditer(text):
        candidate = m.group(1)
        try:
            json.loads(candidate)
            objs.append((m.start(1), m.end(1), candidate))
        except Exception:
            # try replacing single quotes
            try:
                js = candidate.replace("'", '"')
                json.loads(js)
                objs.append((m.start(1), m.end(1), js))
            except Exception:
                continue

    # Then find any JSON-like block that contains relevant fields
    for m in JSON_FIELD_RE.finditer(text):
        candidate = m.group(0)
        try:
            json.loads(candidate)
            objs.append((m.start(0), m.end(0), candidate))
        except Exception:
            try:
                js = candidate.replace("'", '"')
                json.loads(js)
                objs.append((m.start(0), m.end(0), js))
            except Exception:
                continue

    # As last resort, attempt brute-force scanning for balanced braces
    if not objs:
        n = len(text)
        for i, ch in enumerate(text):
            if ch != "{":
                continue
            depth = 0
            for j in range(i, n):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = text[i : j + 1]
                        try:
                            parsed = json.loads(candidate)
                            # only accept if contains ed25519_pk or ed25519_sig
                            if isinstance(parsed, dict) and (
                                "ed25519_pk" in parsed
                                or "ed25519_sig" in parsed
                                or "hello_canonical" in parsed
                            ):
                                objs.append((i, j + 1, candidate))
                        except Exception:
                            pass
                        break
    return objs


def load_keys_from_dir(keys_dir: str) -> Dict[str, Ed25519PublicKey]:
    keys = {}
    if not CRYPTO_AVAILABLE:
        print(
            "cryptography library not available: cannot load PEM keys. Install cryptography to enable key parsing."
        )
        return keys
    if not os.path.isdir(keys_dir):
        return keys
    for fname in os.listdir(keys_dir):
        path = os.path.join(keys_dir, fname)
        if not os.path.isfile(path):
            continue
        try:
            data = open(path, "rb").read()
            # try public key PEM
            try:
                pub = serialization.load_pem_public_key(data, backend=default_backend())
                if isinstance(pub, Ed25519PublicKey):
                    keys[fname] = pub
                    continue
            except Exception:
                pass
            # try private key PEM and derive public
            try:
                priv = serialization.load_pem_private_key(
                    data, password=None, backend=default_backend()
                )
                pub = priv.public_key()
                if isinstance(pub, Ed25519PublicKey):
                    keys[fname] = pub
                    continue
            except Exception:
                pass
            # try if file contains raw base64 or hex
            txt = data.strip()
            for _ in (0,):
                try:
                    raw = base64.b64decode(txt)
                    if len(raw) == 32:
                        pub = Ed25519PublicKey.from_public_bytes(raw)
                        keys[fname] = pub
                        break
                except Exception:
                    pass
        except Exception:
            pass
    return keys


def extract_signature_from_json(obj: Dict[str, Any]) -> Optional[bytes]:
    # common fields
    for k in ("ed25519_sig", "sig", "signature", "ed25519_signature"):
        if k in obj:
            val = obj[k]
            if isinstance(val, str):
                # try base64 then hex
                try:
                    return base64.b64decode(val)
                except Exception:
                    try:
                        return bytes.fromhex(val)
                    except Exception:
                        return None
            elif isinstance(val, (bytes, bytearray)):
                return bytes(val)
    return None


def extract_pubkey_from_json(obj: Dict[str, Any]) -> Optional[bytes]:
    for k in ("ed25519_pk", "ed25519_pub", "pubkey", "pub_key", "identity_pub"):
        if k in obj:
            val = obj[k]
            if isinstance(val, str):
                try:
                    return base64.b64decode(val)
                except Exception:
                    try:
                        return bytes.fromhex(val)
                    except Exception:
                        return val.encode()
            elif isinstance(val, (bytes, bytearray)):
                return bytes(val)
    return None


def canonical_json(obj: Dict[str, Any]) -> bytes:
    # produce stable canonical representation: sort keys, compact separators
    # exclude known signature fields
    obj2 = {
        k: v
        for k, v in obj.items()
        if k not in ("ed25519_sig", "sig", "signature", "hello_canonical")
    }
    return json.dumps(obj2, separators=(",", ":"), sort_keys=True).encode("utf-8")


def try_verify_with_public(
    pubkey_obj: Ed25519PublicKey, message: bytes, signature: bytes
) -> bool:
    try:
        pubkey_obj.verify(signature, message)
        return True
    except Exception:
        return False


def try_verify_with_raw_pubbytes(
    pubbytes: bytes, message: bytes, signature: bytes
) -> bool:
    if not CRYPTO_AVAILABLE:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(pubbytes)
        return try_verify_with_public(pub, message, signature)
    except Exception:
        return False


def analyze_logs(log_paths: List[str], keys_dir: Optional[str]) -> List[Dict[str, Any]]:
    keys = {}
    if keys_dir:
        keys = load_keys_from_dir(keys_dir)
    results = []
    for lp in log_paths:
        if not os.path.isfile(lp):
            continue
        raw_text = open(lp, "r", errors="ignore").read()
        text = strip_ansi(raw_text)
        objs = find_json_objects(text)
        for s, e, json_text in objs:
            note = []
            try:
                parsed = json.loads(json_text)
            except Exception:
                try:
                    parsed = json.loads(json_text.replace("'", '"'))
                except Exception:
                    continue
            # heuristics: consider this JSON if contains 'HELLO' token or hello_canonical or ed25519_sig
            contains_hello = False
            if isinstance(parsed, dict):
                for v in parsed.values():
                    if isinstance(v, str) and "HELLO" in v:
                        contains_hello = True
                        break
                if (
                    "hello_canonical" in parsed
                    or extract_signature_from_json(parsed) is not None
                    or "ed25519_pk" in parsed
                ):
                    contains_hello = True
            if not contains_hello:
                continue

            sig = extract_signature_from_json(parsed)
            pubbytes = extract_pubkey_from_json(parsed)
            # message
            if "hello_canonical" in parsed and isinstance(
                parsed["hello_canonical"], str
            ):
                try:
                    message = base64.b64decode(parsed["hello_canonical"])
                except Exception:
                    message = parsed["hello_canonical"].encode("utf-8")
            else:
                message = canonical_json(parsed)

            signature_valid = None
            matched_key = None
            if sig is None:
                note.append("no signature found")
                signature_valid = False
            else:
                # if pubbytes present, try directly
                if pubbytes:
                    if try_verify_with_raw_pubbytes(pubbytes, message, sig):
                        signature_valid = True
                        note.append("verified with pub in JSON")
                    else:
                        signature_valid = False
                        note.append("pub in JSON failed")
                # try keys from keys_dir
                if signature_valid is not True and keys:
                    for kfname, kobj in keys.items():
                        if try_verify_with_public(kobj, message, sig):
                            signature_valid = True
                            matched_key = kfname
                            note.append(f"verified with key {kfname}")
                            break
                # as last resort, try all raw bytes sequences in keys dir loaded as 32-byte raw
                if signature_valid is not True and keys_dir and CRYPTO_AVAILABLE:
                    for fname in os.listdir(keys_dir):
                        path = os.path.join(keys_dir, fname)
                        try:
                            data = open(path, "rb").read().strip()
                            try:
                                raw = base64.b64decode(data)
                            except Exception:
                                try:
                                    raw = bytes.fromhex(data.decode("utf-8"))
                                except Exception:
                                    continue
                            if len(raw) == 32:
                                if try_verify_with_raw_pubbytes(raw, message, sig):
                                    signature_valid = True
                                    matched_key = fname + " (raw)"
                                    note.append(f"verified with raw {fname}")
                                    break
                        except Exception:
                            pass
                if signature_valid is None:
                    signature_valid = False

            entry = {
                "source_file": lp,
                "start_index": s,
                "end_index": e,
                "json": parsed,
                "signature_present": sig is not None,
                "signature_valid": signature_valid,
                "matched_key": matched_key,
                "notes": "; ".join(note),
            }
            # try to extract timestamps / session_id / peer_id
            for fname in ("timestamp", "time", "ts"):
                if fname in parsed:
                    entry["timestamp"] = parsed[fname]
                    break
            for fname in ("session_id", "session", "sessionid"):
                if fname in parsed:
                    entry["session_id"] = parsed[fname]
                    break
            for fname in ("peer_id", "peer", "peerid", "id"):
                if fname in parsed:
                    entry["peer_id"] = parsed[fname]
                    break
            results.append(entry)
    return results


def write_reports(results: List[Dict[str, Any]], out_json: str, out_csv: str):
    open(out_json, "w").write(json.dumps(results, indent=2, default=str))
    if out_csv:
        keys = [
            "source_file",
            "timestamp",
            "peer_id",
            "session_id",
            "signature_present",
            "signature_valid",
            "matched_key",
            "notes",
        ]
        with open(out_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in results:
                row = {k: r.get(k, "") for k in keys}
                w.writerow(row)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--logs", nargs="*", help="log files to analyze")
    p.add_argument("--keys", default="keys", help="directory with key files to try")
    p.add_argument("--out-json", default="hello_report.json")
    p.add_argument("--out-csv", default="hello_report.csv")
    args = p.parse_args()

    default_logs = [
        "pqvpn_v4.0.2_quantum.log",
        "alice.log",
        "bob.log",
        "alice_run.log",
        "bob_run.log",
        "pqvpn.log",
        "alice.out",
        "bob.out",
        "gui_debug.log",
    ]
    logs = args.logs if args.logs else [p for p in default_logs if os.path.isfile(p)]
    print("Analyzing logs:", logs)
    results = analyze_logs(logs, args.keys)
    print(f"Found {len(results)} candidate HELLO JSON objects (matching heuristics).")
    write_reports(results, args.out_json, args.out_csv)
    print("Wrote", args.out_json, args.out_csv)
