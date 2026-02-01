#!/usr/bin/env python3
"""
Quick verifier: parse pqvpn_v4.0.2_quantum.log for HELLO payloads and verify Ed25519 signatures.
Usage: python3 verify_ed25519.py
"""

import re
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519

LOG = Path("pqvpn_v4.0.2_quantum.log")
if not LOG.exists():
    print("Log file not found:", LOG)
    raise SystemExit(1)

text = LOG.read_text()

# Match raw payloads logged by receiver: 'DEBUG raw hello payload: { ... }'
raw_re = re.compile(r"DEBUG\s*-\s*DEBUG raw hello payload: (\{.*?\})(?=\n)", re.S)
# Fallback: match any JSON-like HELLO payloads that include ed25519_sig
payload_re = re.compile(r'\{[^}]*"ed25519_sig"[^}]*\}', re.S)
# Also extract 'DEBUG signing hello_json' entries if present
signing_re = re.compile(r"DEBUG\s*-\s*DEBUG signing hello_json: (\{.*?\})", re.S)

raws = raw_re.findall(text)
if raws:
    candidates = raws
else:
    # fallback to broader payload matches
    candidates = payload_re.findall(text)

signings = signing_re.findall(text)

print(
    f"Found {len(candidates)} HELLO payload candidates and {len(signings)} signing-JSON entries in log"
)

results = []
for i, p in enumerate(candidates, 1):
    try:
        payload = json.loads(p)
    except Exception as e:
        # Try to fix single quotes / trailing commas
        try:
            payload = json.loads(p.replace("'", '"'))
        except Exception as e2:
            print(f"[{i}] JSON parse failed: {e} / {e2}")
            continue

    ed_sig_hex = payload.get("ed25519_sig")
    ed_pk_hex = payload.get("ed25519_pk")
    nickname = payload.get("nickname")
    peer_id = payload.get("peer_id")

    if not ed_sig_hex or not ed_pk_hex:
        print(
            f"[{i}] missing signature or public key in payload, keys: {list(payload.keys())[:10]}"
        )
        continue

    # Determine canonical message to verify
    if "hello_canonical" in payload and isinstance(payload["hello_canonical"], str):
        msg = payload["hello_canonical"]
        used = "hello_canonical"
    else:
        # Reconstruct canonical JSON with the same ordering and separators used by code
        try:
            hello_data = {
                "peer_id": payload["peer_id"],
                "nickname": payload["nickname"],
                "ed25519_pk": payload["ed25519_pk"],
                "x25519_pk": payload.get("x25519_pk"),
                "kyber_pk": payload["kyber_pk"],
                "mldsa_pk": payload["mldsa_pk"],
                "timestamp": payload["timestamp"],
            }
            msg = json.dumps(hello_data, sort_keys=True, separators=(",", ":"))
            used = "reconstructed"
        except Exception as e:
            print(f"[{i}] cannot reconstruct canonical JSON: {e}")
            continue

    try:
        ed_pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(ed_pk_hex))
        sig = bytes.fromhex(ed_sig_hex)
    except Exception as e:
        print(f"[{i}] key/sig hex decode error: {e}")
        continue

    try:
        ed_pk.verify(sig, msg.encode())
        ok = True
    except Exception as e:
        ok = False
        verify_err = str(e)

    print("---")
    print(f"[{i}] peer={nickname} id={peer_id} used={used} ok={ok}")
    if not ok:
        print(" verify_error:", verify_err)
        print(" ed25519_pk (start):", ed_pk_hex[:64])
        print(" ed25519_sig len:", len(ed_sig_hex))
        print(" message (first 400 chars):")
        print(msg[:400])
        # If signing entries are present, try to find the closest signing JSON
        if signings:
            for s in signings[-5:]:
                # quick check whether signing JSON shares ed25519_pk
                try:
                    js = json.loads(s)
                    if js.get("ed25519_pk") == ed_pk_hex:
                        print(" Found a signing JSON with same ed25519_pk (sample):")
                        print(json.dumps(js, sort_keys=True)[:400])
                        break
                except:
                    continue

    results.append({"peer": nickname, "peer_id": peer_id, "used": used, "ok": ok})

# Summary
succeed = sum(1 for r in results if r["ok"])
print("=== SUMMARY ===")
print(
    f"Total candidates: {len(results)}, verified ok: {succeed}, failed: {len(results) - succeed}"
)

if any(not r["ok"] for r in results):
    print(
        "\nThere are verification failures. Please copy the failing block(s) above or run this script and attach the output."
    )
else:
    print("\nAll HELLO payload signatures verified OK.")
