"""
Crypto Module for PQVPN.
- Contains functions for cryptographic operations.
- Supports fallback for environments without oqs-python.
"""

import logging
import re
from typing import Any, Optional

try:
    from oqs import oqs  # type: ignore
except ImportError:
    oqs = None
    logging.warning("oqs-python not available. Hybrid cryptography features will be disabled.")

logger = logging.getLogger("pqvpn.crypto")


class QuantumKeyManager:
    """Handles post-quantum cryptographic operations."""

    def __init__(self):
        self.oqs_available = oqs is not None
        self.kem_algorithm = None
        self.signature_algorithm = None

        if self.oqs_available:
            self._probe_algorithms()

    def _probe_algorithms(self):
        """Determine available KEM and signature algorithms."""
        enabled_kems = oqs.get_enabled_KEMs() if hasattr(oqs, "get_enabled_KEMs") else []
        enabled_sigs = oqs.get_enabled_Signatures() if hasattr(oqs, "get_enabled_Signatures") else []

        for kem in enabled_kems:
            if "kyber1024" in kem.lower():
                self.kem_algorithm = kem
                break

        for sig in enabled_sigs:
            if "ml-dsa-87" in sig.lower():
                self.signature_algorithm = sig
                break

        if self.kem_algorithm and self.signature_algorithm:
            logger.info(f"OQS Algorithms Selected: KEM={self.kem_algorithm}, SIG={self.signature_algorithm}")

    def kem_keygen(self):
        """Generate Key Encapsulation Mechanism (KEM) key pair."""
        if not self.oqs_available or not self.kem_algorithm:
            raise RuntimeError("KEM key generation requires oqs-python.")

        kem = oqs.KeyEncapsulation(self.kem_algorithm)
        public_key, secret_key = kem.generate_keypair()
        return public_key, secret_key

    def kem_encaps(self, public_key):
        """Encapsulate a shared secret using the selected KEM algorithm."""
        if not self.oqs_available or not self.kem_algorithm:
            raise RuntimeError("KEM encapsulation requires oqs-python.")

        kem = oqs.KeyEncapsulation(self.kem_algorithm)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def kem_decaps(self, ciphertext, private_key):
        """Decapsulate a shared secret using the selected KEM algorithm."""
        if not self.oqs_available or not self.kem_algorithm:
            raise RuntimeError("KEM decapsulation requires oqs-python.")

        kem = oqs.KeyEncapsulation(self.kem_algorithm)
        shared_secret = kem.decap_secret(ciphertext, private_key)
        return shared_secret

    def sig_keygen(self):
        """Generate a signature key pair using the selected algorithm."""
        if not self.oqs_available or not self.signature_algorithm:
            raise RuntimeError("Signature key generation requires oqs-python.")

        sig = oqs.Signature(self.signature_algorithm)
        public_key, private_key = sig.generate_keypair()
        return public_key, private_key

    def sign(self, private_key, data):
        """Sign data using the private key."""
        if not self.oqs_available or not self.signature_algorithm:
            raise RuntimeError("Signing requires oqs-python.")

        signer = oqs.Signature(self.signature_algorithm)
        signature = signer.sign(data, private_key)
        return signature

    def verify(self, public_key, data, signature):
        """Verify a signature against data and a public key."""
        if not self.oqs_available or not self.signature_algorithm:
            raise RuntimeError("Verification requires oqs-python.")

        verifier = oqs.Signature(self.signature_algorithm)
        result = verifier.verify(data, signature, public_key)
        return result


def normalize_input(data: Any) -> Optional[bytes]:
    """Normalize input to bytes, handling various formats (base64, hex, etc.)."""
    if data is None:
        return None
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        if re.fullmatch("[0-9a-fA-F]+", data):
            return bytes.fromhex(data)
        try:
            import base64

            return base64.b64decode(data)
        except Exception:
            return data.encode("utf-8")
    return None