# Quick test script for OQS-related functions in main.py
import importlib
import sys

try:
    m = importlib.import_module("main")
except Exception as e:
    print("Failed to import main.py:", e)
    sys.exit(2)

print("OQSPY_AVAILABLE:", getattr(m, "OQSPY_AVAILABLE", None))
print("OQSPY_KEMALG:", getattr(m, "OQSPY_KEMALG", None))
print("OQSPY_SIGALG:", getattr(m, "OQSPY_SIGALG", None))

# KEM test
try:
    pk, sk = m.pq_kem_keygen()
    print(
        "KEM: pk_len=",
        len(pk) if pk is not None else None,
        " sk_len=",
        len(sk) if sk is not None else None,
    )
    ct, ss1 = m.pq_kem_encaps(pk)
    ss2 = m.pq_kem_decaps(ct, sk)
    print("KEM: shared secrets equal?", ss1 == ss2)
except Exception as e:
    print("KEM test failed:", e)

# Signature test
try:
    pk_sig, sk_sig = m.pq_sig_keygen()
    print(
        "SIG: pk_len=",
        len(pk_sig) if pk_sig is not None else None,
        " sk_len=",
        len(sk_sig) if sk_sig is not None else None,
    )
    msg = b"Hello OQS from main.py test"
    sig = m.pq_sig_sign(sk_sig, msg)
    print("SIG: signature len=", len(sig) if sig is not None else None)
    ok, attempts = m.pq_sig_verify_debug(pk_sig, msg, sig)
    print("SIG verify (debug) ok=", ok)
    print("SIG verify (boolean) ok=", m.pq_sig_verify(pk_sig, msg, sig))
    tampered_ok = m.pq_sig_verify(pk_sig, msg + b"X", sig)
    print("SIG verify tampered (should be False):", tampered_ok)
except Exception as e:
    print("Signature test failed:", e)

print("Done")
