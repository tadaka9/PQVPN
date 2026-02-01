# Compatibility shim for different liboqs Python wrapper layouts
# Some installations expose the oqs API as `oqs` (module) while some expose
# a nested `oqs.oqs` object. Tests and code expect `oqs.oqs` to exist in many
# places; ensure we normalize by pointing `oqs.oqs` to the module when missing.
try:
    import oqs
    # If the nested attribute `oqs.oqs` is missing, make it point to the module
    if not hasattr(oqs, "oqs"):
        setattr(oqs, "oqs", oqs)
except Exception:
    # Import failure handled by callers; keep shim quiet
    pass
