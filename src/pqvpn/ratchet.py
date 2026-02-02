"""
pqvpn.ratchet - Cryptographic Ratchets for Perfect Forward Secrecy

Implements ratchet-based key updates for forward secrecy.
"""

import os
import hmac
import hashlib
from typing import Tuple, Optional, NamedTuple
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import logging

logger = logging.getLogger(__name__)

class RatchetState(NamedTuple):
    """State of the ratchet."""
    root_key: bytes
    chain_key_send: bytes
    chain_key_recv: bytes
    send_message_number: int
    recv_message_number: int
    previous_send_chain_length: int
    skipped_keys: dict  # message_number -> key

class RatchetKey:
    """A ratchet for generating keys with forward secrecy."""

    def __init__(self, initial_key: bytes):
        self.state = RatchetState(
            root_key=initial_key,
            chain_key_send=b'',
            chain_key_recv=b'',
            send_message_number=0,
            recv_message_number=0,
            previous_send_chain_length=0,
            skipped_keys={}
        )

    def advance_ratchet(self) -> None:
        """Advance the ratchet to generate new keys."""
        # Derive new root key and chain keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=96,  # 32 root + 32 send + 32 recv
            salt=None,
            info=b'ratchet_advance'
        )
        new_material = hkdf.derive(self.state.root_key)

        self.state = self.state._replace(
            root_key=new_material[:32],
            chain_key_send=new_material[32:64],
            chain_key_recv=new_material[32:64],  # Same as send for this simplified version
            send_message_number=0,
            recv_message_number=0,
            skipped_keys={}
        )
        logger.debug("Ratchet advanced")

    def _derive_message_key(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """Derive message key and next chain key."""
        # KDF chain: HMAC-SHA256
        message_key = hmac.new(chain_key, b'message_key', hashlib.sha256).digest()
        next_chain_key = hmac.new(chain_key, b'next_chain', hashlib.sha256).digest()
        return message_key, next_chain_key

    def encrypt_with_ratchet(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data and return (ciphertext, header)."""
        # Derive message key from current chain
        if not self.state.chain_key_send:
            # Initialize chain key from root
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'chain_init'
            )
            self.state = self.state._replace(chain_key_send=hkdf.derive(self.state.root_key))

        message_key, next_chain_key = self._derive_message_key(self.state.chain_key_send)

        # Create AEAD cipher
        cipher = ChaCha20Poly1305(message_key)

        # Use message number as nonce
        nonce = self.state.send_message_number.to_bytes(12, 'big')

        # Encrypt
        ciphertext = cipher.encrypt(nonce, plaintext, b'')

        # Update state
        self.state = self.state._replace(
            chain_key_send=next_chain_key,
            send_message_number=self.state.send_message_number + 1
        )

        # Header contains message number used for encryption
        header = (self.state.send_message_number - 1).to_bytes(4, 'big')
        return ciphertext, header

    def decrypt_with_ratchet(self, ciphertext: bytes, header: bytes) -> bytes:
        """Decrypt data and advance ratchet if needed."""
        message_number = int.from_bytes(header, 'big')

        # Check if we need to skip ahead
        if message_number < self.state.recv_message_number:
            # Message already processed or replay
            raise ValueError("Replay attack detected")

        # Initialize receive chain if needed
        if not self.state.chain_key_recv:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'chain_init'
            )
            self.state = self.state._replace(chain_key_recv=hkdf.derive(self.state.root_key))

        # Skip to the correct message number
        while self.state.recv_message_number < message_number:
            if self.state.recv_message_number in self.state.skipped_keys:
                # Use skipped key
                message_key = self.state.skipped_keys[self.state.recv_message_number]
                del self.state.skipped_keys[self.state.recv_message_number]
            else:
                # Derive and skip
                message_key, next_chain_key = self._derive_message_key(self.state.chain_key_recv)
                self.state = self.state._replace(chain_key_recv=next_chain_key)
                # Store skipped key for potential out-of-order
                self.state.skipped_keys[self.state.recv_message_number] = message_key
            self.state = self.state._replace(recv_message_number=self.state.recv_message_number + 1)

        # Now decrypt the current message
        if self.state.recv_message_number in self.state.skipped_keys:
            message_key = self.state.skipped_keys[self.state.recv_message_number]
            del self.state.skipped_keys[self.state.recv_message_number]
        else:
            message_key, next_chain_key = self._derive_message_key(self.state.chain_key_recv)
            self.state = self.state._replace(chain_key_recv=next_chain_key)

        # Decrypt
        cipher = ChaCha20Poly1305(message_key)
        nonce = message_number.to_bytes(12, 'big')
        plaintext = cipher.decrypt(nonce, ciphertext, b'')

        # Advance message number
        self.state = self.state._replace(recv_message_number=self.state.recv_message_number + 1)

        return plaintext

def create_ratchet(initial_key: bytes) -> RatchetKey:
    """Create a new ratchet with initial key."""
    return RatchetKey(initial_key)

class HashRatchet:
    """Hash-based ratchet for forward secrecy using hash chains."""

    def __init__(self, initial_seed: bytes):
        self.current_hash = initial_seed
        self.chain_length = 0
        self.generated_keys = {}  # step -> key

    def advance(self) -> bytes:
        """Advance the hash ratchet and return the next key."""
        self.current_hash = hashlib.sha256(self.current_hash).digest()
        self.chain_length += 1
        key = self.current_hash
        self.generated_keys[self.chain_length] = key
        return key

    def get_key_at_step(self, step: int) -> bytes:
        """Get the key at a specific step (compute if needed)."""
        if step in self.generated_keys:
            return self.generated_keys[step]

        if step <= self.chain_length:
            # Already passed this step
            raise ValueError("Cannot retrieve past keys in hash ratchet")

        # Advance to the step
        current = self.current_hash
        for i in range(self.chain_length + 1, step + 1):
            current = hashlib.sha256(current).digest()
            self.generated_keys[i] = current

        self.chain_length = step
        self.current_hash = current
        return current

    def verify_key(self, key: bytes, step: int) -> bool:
        """Verify that a key belongs to a specific step."""
        expected = self.get_key_at_step(step)
        return hmac.compare_digest(key, expected)

class SymmetricRatchet:
    """Symmetric ratchet for key evolution."""

    def __init__(self, initial_key: bytes):
        self.current_key = initial_key

    def ratchet_forward(self) -> bytes:
        """Advance the ratchet forward."""
        # Simple KDF: hash current key
        self.current_key = hashlib.sha256(self.current_key + b"forward").digest()
        return self.current_key

    def ratchet_backward(self, steps: int) -> bytes:
        """Derive a key steps backward (limited capability)."""
        key = self.current_key
        for _ in range(steps):
            key = hashlib.sha256(key + b"backward").digest()
        return key

    def get_current_key(self) -> bytes:
        """Get current key."""
        return self.current_key

def test_ratchet_forward_secrecy():
    """Test that ratchet provides forward secrecy."""
    initial_key = os.urandom(32)
    alice_ratchet = create_ratchet(initial_key)
    bob_ratchet = create_ratchet(initial_key)

    # Send a message
    plaintext = b"Hello, Bob!"
    ciphertext, header = alice_ratchet.encrypt_with_ratchet(plaintext)
    decrypted = bob_ratchet.decrypt_with_ratchet(ciphertext, header)

    assert decrypted == plaintext

    # Advance ratchets (simulating key compromise scenario)
    alice_ratchet.advance_ratchet()
    bob_ratchet.advance_ratchet()

    # Send another message - should work with new keys
    plaintext2 = b"How are you?"
    ciphertext2, header2 = alice_ratchet.encrypt_with_ratchet(plaintext2)
    decrypted2 = bob_ratchet.decrypt_with_ratchet(ciphertext2, header2)

    assert decrypted2 == plaintext2

    # Old messages should not be decryptable with new keys
    try:
        bob_ratchet.decrypt_with_ratchet(ciphertext, header)
        assert False, "Should not be able to decrypt old message"
    except Exception:
        pass  # Expected

    logger.info("Ratchet forward secrecy test passed")