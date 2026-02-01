"""
PQ signature helpers (extracted from main.py for clarity and testability).
Provides:
 - pq_sig_sign(secret_key_bytes, data, alg=None) -> signature bytes
 - pq_sig_verify_debug(public_key_bytes, data, signature, alg=None) -> (bool, attempts)
 - pq_sig_verify(public_key_bytes, data, signature, alg=None) -> bool
 - pq_sig_verify_variants(public_key_bytes, payload_dict, signature_field, field_order=None) -> (bool, attempts)

This module tries to use the `oqs` Python binding when available and falls back to
best-effort normalization and attempts patterns.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any, List, Tuple, Optional

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

try:
    # Require the nested import pattern used in this project to avoid ABI surprises
    from oqs import oqs as oqs_pkg  # type: ignore
except Exception:
    oqs_pkg = None  # type: ignore
    logger.error(
        "Nested import 'from oqs import oqs' failed; liboqs-python may not be available or exposed as nested object."
    )


def _to_bytes(x: Any) -> Optional[bytes]:
    if x is None:
        return None
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, memoryview):
        return bytes(x)
    if isinstance(x, str):
        s = x.strip()
        # try hex
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
            try:
                return bytes.fromhex(s)
            except Exception:
                pass
        # try base64
        try:
            return base64.b64decode(s)
        except Exception:
            pass
        return s.encode()
    try:
        return bytes(x)
    except Exception:
        return None


def pq_sig_verify_debug(
    pk: Any, data: bytes, sig: Any, alg: Optional[str] = None
) -> Tuple[bool, List[Tuple[str, Any]]]:
    """Attempt many verify variants and return (ok, attempts).

    Each attempt is recorded as (description, result_or_exception).
    """
    attempts: List[Tuple[str, Any]] = []

    try:
        sigcls = getattr(oqs_pkg, "Signature", None) if oqs_pkg is not None else None
        if sigcls is None:
            return False, [("oqs-missing", "Signature API not available")]

        pkb = _to_bytes(pk)
        if pkb is None:
            return False, [
                ("pk-normalize-failed", "public key could not be normalized")
            ]

        sigb = _to_bytes(sig)
        if sigb is None:
            return False, [
                ("sig-normalize-failed", "signature could not be normalized")
            ]

        if isinstance(data, (bytes, bytearray)):
            original = bytes(data)
        else:
            try:
                original = str(data).encode()
            except Exception:
                original = b""

        # Try direct oqs binding first
        try:
            with sigcls(alg) as verifier:
                try:
                    r = verifier.verify(original, sigb, pkb)
                    attempts.append(("oqs.verify(original,sig,pk)", r))
                    if r:
                        return True, attempts
                except Exception as e:
                    attempts.append(("oqs.verify(exc)", str(e)))
        except Exception:
            pass

        # Build simple canonical variants
        variants = [original, original.strip()]
        try:
            variants.append(original.hex().encode())
        except Exception:
            pass
        try:
            variants.append(base64.b64encode(original))
        except Exception:
            pass
        try:
            variants.append(original.decode(errors="ignore").encode())
        except Exception:
            pass

        # JSON canonicalizations
        if original.lstrip().startswith(b"{"):
            try:
                obj = json.loads(original)
                variants.append(
                    json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
                )
                variants.append(
                    json.dumps(obj, separators=(",", ":"), sort_keys=False).encode()
                )
            except Exception:
                pass

        # Hash variants
        try:
            for h in (
                hashlib.sha256(original).digest(),
                hashlib.sha512(original).digest(),
            ):
                variants.append(h)
                variants.append(h.hex().encode())
                variants.append(base64.b64encode(h))
        except Exception:
            pass

        # dedupe
        seen = set()
        uniq = []
        for v in variants:
            if v in seen:
                continue
            seen.add(v)
            uniq.append(v)

        # attempt verify for each variant
        for v in uniq:
            try:
                with sigcls(alg) as verifier:
                    try:
                        r = verifier.verify(v, sigb, pkb)
                        attempts.append(("verify(var)", r))
                        if r:
                            return True, attempts
                    except Exception as e:
                        attempts.append(("verify(var)->exc", str(e)))

                    # try bound constructor
                    try:
                        with sigcls(alg, public_key=pkb) as bver:
                            bv = getattr(bver, "verify", None)
                            if bv and callable(bv):
                                try:
                                    r = bv(v, sigb)
                                    attempts.append(("bound.verify(var)", r))
                                    if r:
                                        return True, attempts
                                except Exception as e:
                                    attempts.append(("bound.verify(var)->exc", str(e)))
                    except Exception:
                        pass
            except Exception as e:
                attempts.append(("verifier-construction-exc", str(e)))

        return False, attempts
    except Exception as e:
        return False, [("exception", str(e))]


def pq_sig_verify(pk: Any, data: bytes, sig: Any, alg: Optional[str] = None) -> bool:
    ok, _ = pq_sig_verify_debug(pk, data, sig, alg=alg)
    return ok


def pq_sig_sign(sk: Any, data: bytes, alg: Optional[str] = None) -> bytes:
    """Sign using oqs Signature if available. sk is expected to be secret key bytes or object acceptable to oqs wrapper."""
    sigcls = getattr(oqs_pkg, "Signature", None) if oqs_pkg is not None else None
    if sigcls is None:
        raise RuntimeError("oqs Signature API not available for signing")

    # try with provided secret_key argument
    try:
        with sigcls(alg, secret_key=sk) as signer:
            # prefer sign_with_ctx_str if available
            if hasattr(signer, "sign_with_ctx_str"):
                try:
                    return signer.sign_with_ctx_str(data, b"")
                except Exception:
                    pass
            return signer.sign(data)
    except Exception as e:
        logger.error(f"pq_sig_sign failed: {e}")
        raise


def pq_sig_verify_variants(
    mldsa_pk_bytes: Any,
    j_payload: Any,
    sig_field: Any,
    field_order: Optional[List[str]] = None,
) -> Tuple[bool, List[Any]]:
    """Try canonicalization variants of `j_payload` (dict) and verify signature field."""
    attempts: List[Any] = []
    sigb = _to_bytes(sig_field)
    if sigb is None:
        return False, [("sig-normalize-failed", "signature normalization failed")]

    # Build candidate message bytes
    variants = []
    try:
        if field_order:
            variants.append(
                (
                    "canonical_ordered",
                    json.dumps(
                        {k: j_payload.get(k) for k in field_order if k in j_payload},
                        separators=(",", ":"),
                        sort_keys=False,
                    ).encode(),
                )
            )
    except Exception:
        pass
    try:
        variants.append(
            (
                "canonical_sorted",
                json.dumps(j_payload, separators=(",", ":"), sort_keys=True).encode(),
            )
        )
    except Exception:
        pass
    try:
        variants.append(
            (
                "json_unsorted",
                json.dumps(j_payload, separators=(",", ":"), sort_keys=False).encode(),
            )
        )
    except Exception:
        pass

    # add hex/base64 variants for each
    snap = list(variants)
    for name, v in snap:
        try:
            variants.append((f"hex_{name}", v.hex().encode()))
        except Exception:
            pass
        try:
            variants.append((f"b64_{name}", base64.b64encode(v)))
        except Exception:
            pass

    # dedupe
    seen = set()
    ordered = []
    for name, v in variants:
        if v is None:
            continue
        if v in seen:
            continue
        seen.add(v)
        ordered.append((name, v))

    for name, v in ordered:
        try:
            ok, att = pq_sig_verify_debug(mldsa_pk_bytes, v, sigb)
            attempts.append((name, ok, att))
            if ok:
                return True, attempts
        except Exception as e:
            attempts.append((name, False, [("exception", str(e))]))

    return False, attempts
