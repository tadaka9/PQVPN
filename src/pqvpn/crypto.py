"""
pqvpn.crypto - Post-quantum crypto helpers extracted from main.py

This module provides a lightweight, mostly-compatible extraction of the
post-quantum helper functions that lived inside PQVPN/main.py.

Public API (subset used by main.py):
- OQSPY_AVAILABLE, OQSPY_KEMALG, OQSPY_SIGALG, (length placeholders)
- pq_kem_keygen, pq_kem_encaps, pq_kem_decaps
- pq_sig_keygen, pq_sig_sign, pq_sig_verify_debug, pq_sig_verify

This module tries to import the upstream `oqs` binding (oqs-python).
If it's not available the functions raise RuntimeError when invoked in
hybrid-only mode. This mirrors the behaviour in main.py: callers can
catch the error or run in emulated/test mode.
"""

import base64
import json
import logging
from typing import Any

from .robustness import circuit_breaker, log_with_context

logger = logging.getLogger("pqvpn.crypto")
# Let the main logger configure handlers; avoid adding extra ones here
if not logger.handlers:
    logger.addHandler(logging.NullHandler())

# Public flags/values (kept None/False by default, updated if oqs available)
OQSPY_AVAILABLE = False
OQSPY_KEMALG: str | None = None
OQSPY_SIGALG: str | None = None
OQSPY_KEM_PUBLEN: int | None = None
OQSPY_KEM_SKLEN: int | None = None
OQSPY_KEM_CTLEN: int | None = None
OQSPY_KEM_SSLEN: int | None = None
OQSPY_SIG_PUBLEN: int | None = None
OQSPY_SIG_SKLEN: int | None = None
OQSPY_SIG_SIGLEN: int | None = None

oqs_module = None
try:
    # `from oqs import oqs as oqs_module` is the pattern used in main.py
    from oqs import oqs as oqs_module  # type: ignore

    logger.info("oqs-python nested implementation module loaded")
except Exception:
    oqs_module = None
    logger.debug("oqs-python import failed; PQ features will be unavailable", exc_info=True)

if oqs_module is not None:
    # Discover enabled mechanisms (support different upstream API names)
    enabled_kems_iter = getattr(
        oqs_module,
        "get_enabled_kem_mechanisms",
        getattr(oqs_module, "get_enabled_kems", lambda: []),
    )
    try:
        enabled_kems = (
            list(enabled_kems_iter()) if callable(enabled_kems_iter) else list(enabled_kems_iter)
        )
    except Exception:
        enabled_kems = []

    enabled_sigs_iter = getattr(
        oqs_module,
        "get_enabled_sig_mechanisms",
        getattr(oqs_module, "get_enabled_sigs", lambda: []),
    )
    try:
        enabled_sigs = (
            list(enabled_sigs_iter()) if callable(enabled_sigs_iter) else list(enabled_sigs_iter)
        )
    except Exception:
        enabled_sigs = []

    required_kem = None
    required_sig = None
    for candidate in enabled_kems:
        if "kyber1024" in candidate.lower():
            required_kem = candidate
            break
    for candidate in enabled_sigs:
        if "ml-dsa-87" in candidate.lower() or candidate.lower().startswith("ml-dsa-87"):
            required_sig = candidate
            break

    if required_kem and required_sig:
        OQSPY_AVAILABLE = True
        OQSPY_KEMALG = required_kem
        OQSPY_SIGALG = required_sig
        logger.info(f"oqs-python available - KEM: {OQSPY_KEMALG}, SIG: {OQSPY_SIGALG}")
    else:
        OQSPY_AVAILABLE = False
        logger.warning(
            "oqs-python present but required hybrid algorithms not both enabled; enabled_kems=%r, enabled_sigs=%r",
            enabled_kems,
            enabled_sigs,
        )
else:
    OQSPY_AVAILABLE = False


# ----- small helpers -----


def _pqsig_to_bytes(x: Any) -> bytes | None:
    if x is None:
        return None
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, memoryview):
        return bytes(x)
    if isinstance(x, str):
        s = x.strip()
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
            try:
                return bytes.fromhex(s)
            except Exception:
                pass
        try:
            return base64.b64decode(s)
        except Exception:
            pass
        return s.encode()
    try:
        return bytes(x)
    except Exception:
        return None


# ----- signature helpers -----


def pq_sig_verify_debug(pk: Any, data: bytes, sig: Any, alg: str | None = None):
    """Return (ok: bool, attempts: List[Tuple[str,Any]]) similar to original main.py helper."""
    attempts: list[tuple[str, Any]] = []
    try:
        sigcls = getattr(oqs_module, "Signature", None) if oqs_module is not None else None
        if sigcls is None:
            return False, [("oqs-missing", "Signature API not available")]

        pkb = _pqsig_to_bytes(pk)
        if pkb is None:
            return False, [("pk-normalize-failed", "public key could not be normalized")]

        sigb = _pqsig_to_bytes(sig)
        if sigb is None:
            return False, [("sig-normalize-failed", "signature could not be normalized")]

        if isinstance(data, (bytes, bytearray)):
            original = bytes(data)
        else:
            try:
                original = str(data).encode()
            except Exception:
                original = b""

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

        variants: list[bytes] = [original, original.strip()]
        try:
            variants.append(original.hex().encode())
        except Exception:
            pass
        try:
            variants.append(base64.b64encode(original))
        except Exception:
            pass

        if original.lstrip().startswith(b"{"):
            try:
                obj = json.loads(original)
                variants.append(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())
                variants.append(json.dumps(obj, separators=(",", ":"), sort_keys=False).encode())
            except Exception:
                pass

        seen = set()
        uniq: list[bytes] = []
        for v in variants:
            if v in seen:
                continue
            seen.add(v)
            uniq.append(v)

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


def pq_sig_verify(pk: Any, data: bytes, sig: Any, alg: str | None = None) -> bool:
    ok, _ = pq_sig_verify_debug(pk, data, sig, alg=alg)
    return ok


def pq_sig_sign(sk: Any, data: bytes, alg: str | None = None) -> bytes:
    sigcls = getattr(oqs_module, "Signature", None) if oqs_module is not None else None
    if sigcls is None:
        raise RuntimeError("oqs Signature API not available for signing")
    try:
        with sigcls(alg, secret_key=sk) as signer:
            if hasattr(signer, "sign_with_ctx_str"):
                try:
                    return signer.sign_with_ctx_str(data, b"")
                except Exception:
                    pass
            return signer.sign(data)
    except Exception as e:
        logger.error(f"pq_sig_sign failed: {e}")
        raise


# ----- KEM helpers -----


def pq_kem_keygen() -> tuple[bytes, bytes]:
    """Generate Kyber KEM key pair using oqs if present; otherwise raise.

    Returns (pk, sk) bytes.
    """
    if not OQSPY_AVAILABLE:
        raise RuntimeError("pq_kem_keygen: liboqs not available; hybrid-only mode requires liboqs")
    kenc = getattr(oqs_module, "KeyEncapsulation", None)
    if kenc is None:
        raise RuntimeError("KeyEncapsulation class not found in oqs module")
    with kenc(OQSPY_KEMALG) as kem:
        try:
            res = kem.generate_keypair()
        except Exception:
            res = None

        try:
            sk_export = kem.export_secret_key()
        except Exception:
            sk_export = None

        pk = None
        sk = None
        if isinstance(res, (list, tuple)) and len(res) == 2:
            pk_candidate, sk_candidate = res
            pk = pk_candidate
            if sk_export is None:
                sk = sk_candidate
        else:
            pk = res
            sk = sk_export

        if isinstance(pk, str):
            try:
                if all(c in "0123456789abcdef" for c in pk):
                    pk = bytes.fromhex(pk)  # type: ignore[arg-type]
                else:
                    pk = pk.encode()  # type: ignore[arg-type]
            except Exception:
                pk = pk.encode()  # type: ignore[arg-type]
        if isinstance(sk, str):
            try:
                if all(c in "0123456789abcdef" for c in sk):
                    sk = bytes.fromhex(sk)  # type: ignore[arg-type]
                else:
                    sk = sk.encode()  # type: ignore[arg-type]
            except Exception:
                sk = sk.encode()  # type: ignore[arg-type]

        logger.debug(
            f"Kyber keypair generated via liboqs-python - pk_len={len(pk) if pk else None} sk_len={len(sk) if sk else None}"
        )
        return pk, sk


def pq_kem_encaps(pk: bytes, alg: str | None = None) -> tuple[bytes, bytes]:
    use_alg = alg if alg is not None else OQSPY_KEMALG
    if not OQSPY_AVAILABLE:
        log_with_context(
            "pq_kem_encaps: liboqs not available; hybrid-only mode requires liboqs",
            "error",
            {"alg": use_alg},
        )
        raise RuntimeError("pq_kem_encaps: liboqs not available; hybrid-only mode requires liboqs")
    try:
        ct, ss = circuit_breaker.call(_pq_kem_encaps_internal, pk, use_alg)
        logger.debug(f"{use_alg} encaps via liboqs-python")
        return ct, ss
    except Exception as e:
        log_with_context(f"pq_kem_encaps failed: {e}", "error", {"alg": use_alg})
        raise


def _pq_kem_encaps_internal(pk: bytes, use_alg: str) -> tuple[bytes, bytes]:
    kenc = getattr(oqs_module, "KeyEncapsulation", None)
    if kenc is None:
        raise RuntimeError("KeyEncapsulation class not found in oqs module")
    with kenc(use_alg) as kem:
        ct, ss = kem.encap_secret(pk)
        return ct, ss


def pq_kem_decaps(ct: bytes, sk: bytes, alg: str | None = None) -> bytes:
    use_alg = alg if alg is not None else OQSPY_KEMALG
    if not OQSPY_AVAILABLE:
        log_with_context(
            "pq_kem_decaps: liboqs not available; hybrid-only mode requires liboqs",
            "error",
            {"alg": use_alg},
        )
        raise RuntimeError("pq_kem_decaps: liboqs not available; hybrid-only mode requires liboqs")
    try:
        ss = circuit_breaker.call(_pq_kem_decaps_internal, ct, sk, use_alg)
        logger.debug(f"{use_alg} decaps via liboqs-python")
        return ss
    except Exception as e:
        log_with_context(f"pq_kem_decaps failed: {e}", "error", {"alg": use_alg})
        raise


def _pq_kem_decaps_internal(ct: bytes, sk: bytes, use_alg: str) -> bytes:
    kenc = getattr(oqs_module, "KeyEncapsulation", None)
    if kenc is None:
        raise RuntimeError("KeyEncapsulation class not found in oqs module")
    with kenc(use_alg, secret_key=sk) as kem:
        ss = kem.decap_secret(ct)
        return ss


def check_crypto_health() -> bool:
    """Health check for crypto operations."""
    try:
        # Simple keygen test
        pk, sk = pq_kem_keygen()
        ct, ss1 = pq_kem_encaps(pk)
        ss2 = pq_kem_decaps(ct, sk)
        return ss1 == ss2
    except Exception:
        return False
