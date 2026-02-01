#!/usr/bin/env python3
"""
Log correlation helper for PQVPN
- Parses one or more log files looking for HELLO sent/received events
  and reconstructed HELLO payloads (JSON). Tries to correlate sender
  and receiver by matching public keys (ed25519_pk, mldsa_pk, kyber_pk, x25519_pk)
- Reports signature verification failures and unmatched HELLO messages.

Usage:
  python scripts/log_correlate.py [--files file1 file2 ...]

Defaults look in the repository root for common names.
"""

import re
import json
import argparse
from collections import defaultdict
from pathlib import Path

# Regexes
TS_RE = re.compile(r"^\[([0-9:.]+)\]\s+([A-Z]+)\s+-\s+(.*)$")
HELLO_SENT_RE = re.compile(
    r"HELLO sent(?: to)?(?: .* at)?(?: )?(?:to )?(?P<ip>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(?P<port>\d+)",
    re.IGNORECASE,
)
INIT_HANDSHAKE_RE = re.compile(
    r"Initiating handshake(?: with (?P<nick>[^ ]+))? at (?P<ip>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(?P<port>\d+)"
)
RECONSTRUCTED_JSON_RE = re.compile(
    r"reconstructed hello_json:\s*(\{.*\})", re.IGNORECASE
)
AUDIT_HELLO_SENT_RE = re.compile(
    r"Audit: HELLO_SENT - to (?P<ip>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(?P<port>\d+)"
)
KEEPALIVE_RE = re.compile(
    r"KEEPALIVE from \('(?P<ip>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', (?P<port>\d+)\)"
)
ED25519_FAIL_RE = re.compile(r"Ed25519 signature verification failed", re.IGNORECASE)
MLDSA_FAIL_RE = re.compile(
    r"ML-DSA[- ]?\d+ signature verification failed", re.IGNORECASE
)
PROVIDED_PK_TOO_SHORT_RE = re.compile(
    r"Provided public key too short for (?P<alg>[^ ]+) \(have (?P<have>\d+), need (?P<need>\d+)\)",
    re.IGNORECASE,
)


def parse_files(paths):
    events = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        with p.open("r", errors="ignore") as fh:
            for i, line in enumerate(fh, start=1):
                sline = line.rstrip("\n")
                ts = None
                level = None
                msg = sline
                m_ts = TS_RE.match(sline)
                if m_ts:
                    ts = m_ts.group(1)
                    level = m_ts.group(2)
                    msg = m_ts.group(3)
                rec = {
                    "file": str(p),
                    "line": i,
                    "raw": sline,
                    "ts": ts,
                    "level": level,
                    "msg": msg,
                }

                # check patterns
                m = (
                    HELLO_SENT_RE.search(msg)
                    or AUDIT_HELLO_SENT_RE.search(msg)
                    or INIT_HANDSHAKE_RE.search(msg)
                )
                if m:
                    rec["type"] = "hello_sent"
                    rec["ip"] = m.group("ip")
                    rec["port"] = int(m.group("port"))
                    rec["nick"] = m.groupdict().get("nick")

                m2 = RECONSTRUCTED_JSON_RE.search(msg)
                if m2:
                    rec["type"] = "hello_reconstructed"
                    jtxt = m2.group(1)
                    try:
                        # sometimes log JSON has single quotes or trailing .. try to normalize
                        j = json.loads(jtxt)
                    except Exception:
                        # try replacing single quotes with double quotes in a best-effort manner
                        try:
                            j = json.loads(jtxt.replace("'", '"'))
                        except Exception:
                            j = None
                    rec["hello_json"] = j

                m3 = KEEPALIVE_RE.search(msg)
                if m3:
                    rec["type"] = "keepalive"
                    rec["ip"] = m3.group("ip")
                    rec["port"] = int(m3.group("port"))

                if ED25519_FAIL_RE.search(msg):
                    rec.setdefault("errors", []).append("ed25519_fail")
                if MLDSA_FAIL_RE.search(msg):
                    rec.setdefault("errors", []).append("mldsa_fail")
                mshort = PROVIDED_PK_TOO_SHORT_RE.search(msg)
                if mshort:
                    rec.setdefault("warnings", []).append(
                        {"provided_short": mshort.groupdict()}
                    )

                events.append(rec)
    return events


def index_hellos(events):
    sent = []
    reconstructed = []
    for e in events:
        if e.get("type") == "hello_sent":
            sent.append(e)
        elif e.get("type") == "hello_reconstructed":
            reconstructed.append(e)
    return sent, reconstructed


def match_hellos(sent, reconstructed):
    # build index on public keys for quick matching
    index = defaultdict(list)
    for r in reconstructed:
        j = r.get("hello_json") or {}
        for key in ("ed25519_pk", "mldsa_pk", "kyber_pk", "x25519_pk", "peer_id"):
            val = j.get(key) if isinstance(j, dict) else None
            if val:
                index[(key, val)].append(r)

    results = []
    for s in sent:
        candidates = defaultdict(int)
        sres = {"sent": s, "matches": []}
        # attempt to match by ip/port first (best-effort)
        # then by public keys
        for key in ("ed25519_pk", "mldsa_pk", "kyber_pk", "x25519_pk", "peer_id"):
            # sometimes the sent event contains the json? no, so try to find in nearby lines? skip
            pass
        # collect all reconstructed that have same ip if possible
        ip = s.get("ip")
        port = s.get("port")
        # naive matching: any reconstructed whose raw line mentions the same ip:port or whose JSON contains peer_id/keys present in other logs
        for r in reconstructed:
            score = 0
            # ip mention
            if ip and (ip in r.get("raw", "")):
                score += 2
            # JSON key matches with any known token in sent raw
            j = r.get("hello_json") or {}
            for key in ("ed25519_pk", "mldsa_pk", "kyber_pk", "x25519_pk", "peer_id"):
                val = j.get(key) if isinstance(j, dict) else None
                if not val:
                    continue
                # if the same value appears in the sent raw line (maybe logged elsewhere), boost score
                if val in s.get("raw", ""):
                    score += 4
                # also if other heuristics - we simply record the presence
                # try to find matching public keys across files by searching other sent events later
            if score > 0:
                candidates[r["file"], r["line"]] = score
        # fallback: include top candidates from index if any key values are present in other files
        # Prepare final match list sorted by score
        sorted_matches = sorted(candidates.items(), key=lambda x: -x[1])
        for f_ln, sc in sorted_matches:
            file, line = f_ln
            # retrieve reconstructed object
            rec = next(
                (r for r in reconstructed if r["file"] == file and r["line"] == line),
                None,
            )
            if rec:
                sres["matches"].append({"reconstructed": rec, "score": sc})
        results.append(sres)
    return results


def summarize(events, matches):
    out = []
    # report signature failures
    sig_failures = [e for e in events if "errors" in e]
    out.append("Signature/warnings summary:")
    if not sig_failures:
        out.append("  No explicit signature failure lines found")
    else:
        for e in sig_failures:
            out.append(
                f"  {Path(e['file']).name}:{e['line']}: {e.get('errors')} - raw: {e['raw']}"
            )
    out.append("\nHELLO sent correlation:")
    if not matches:
        out.append("  No HELLO_SENT events found")
    for m in matches:
        s = m["sent"]
        out.append(
            f"- Sent @ {Path(s['file']).name}:{s['line']} -> {s.get('ip')}:{s.get('port')} (nick={s.get('nick')})"
        )
        if not m["matches"]:
            out.append(
                "    No reconstructed HELLO matches found (candidate: matching by public keys not detected)"
            )
        else:
            for cand in m["matches"]:
                r = cand["reconstructed"]
                j = r.get("hello_json")
                keys = []
                if isinstance(j, dict):
                    for k in (
                        "peer_id",
                        "nickname",
                        "ed25519_pk",
                        "x25519_pk",
                        "kyber_pk",
                        "mldsa_pk",
                    ):
                        if j.get(k):
                            keys.append(f"{k}={j.get(k)[:16]}...")
                out.append(
                    f"    Matched {Path(r['file']).name}:{r['line']} score={cand['score']} keys={' '.join(keys)} errors={r.get('errors')}"
                )
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Correlate PQVPN HELLO logs")
    parser.add_argument(
        "--files",
        nargs="+",
        help="Log files to parse",
        default=[
            "pqvpn_v4.0.2_quantum.log",
            "alice.out",
            "bob.out",
            "pqvpn.log",
            "pqvpn_kernel.log",
        ],
    )
    parser.add_argument(
        "--print-all", action="store_true", help="Print all parsed events (debug)"
    )
    args = parser.parse_args()

    paths = [Path(p) for p in args.files]
    existing = [str(p) for p in paths if p.exists()]
    if not existing:
        print(
            "No provided log files exist in working directory. Looked for:", args.files
        )
        return
    events = parse_files(existing)
    sent, reconstructed = index_hellos(events)
    matches = match_hellos(sent, reconstructed)
    if args.print_all:
        for e in events:
            print(e)
    summary = summarize(events, matches)
    print(summary)


if __name__ == "__main__":
    main()
