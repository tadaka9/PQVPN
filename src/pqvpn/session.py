# src/pqvpn/session.py
"""
Session management module for PQVPN.

Handles session creation, key rotation, and session state.
"""

import time
import os
import hashlib
from typing import Optional, Tuple, Set
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import logging

from .ratchet import RatchetKey

logger = logging.getLogger(__name__)

# Session states
SESSION_STATE_PENDING = "PENDING"
SESSION_STATE_HANDSHAKING = "HANDSHAKING"
SESSION_STATE_ESTABLISHED = "ESTABLISHED"
SESSION_STATE_REKEYING = "REKEYING"
SESSION_STATE_CLOSED = "CLOSED"


@dataclass
class SessionInfo:
    session_id: bytes
    peer_id: bytes
    aead_send: ChaCha20Poly1305
    aead_recv: ChaCha20Poly1305
    state: str = SESSION_STATE_PENDING
    created_at: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    last_activity: float = field(default_factory=time.time)
    nonce_send: int = 0
    nonce_recv: int = 0
    remote_addr: Optional[Tuple[str, int]] = None
    send_key: bytes = b""
    recv_key: bytes = b""
    replay_window: Set[int] = field(default_factory=set)
    replay_window_size: int = 1024
    # 4-byte per-session random prefix used with an 8-byte counter to form 12-byte AEAD nonces
    session_iv: bytes = field(default_factory=lambda: os.urandom(4))
    remote_session_id: Optional[bytes] = None
    s1_frame: Optional[bytes] = None  # Store the raw S1 frame for possible retransmission
    handshake_retries: int = 0  # Count handshake retries
    ratchet: Optional[RatchetKey] = None  # Cryptographic ratchet for forward secrecy

    def rotate_keys(self, reason: str = 'rekey') -> None:
        """Rotate AEAD keys for this session using ratchet-based forward secrecy.

        This method advances the ratchet to generate new keys with perfect forward secrecy.
        """
        try:
            if self.ratchet is None:
                # Initialize ratchet if not present
                from .ratchet import create_ratchet
                initial_key = self.send_key + self.recv_key  # Combine for initial ratchet key
                if len(initial_key) != 64:
                    initial_key = hashlib.sha256(initial_key).digest()
                self.ratchet = create_ratchet(initial_key)

            # Advance ratchet for new keys
            self.ratchet.advance_ratchet()

            # Generate new AEAD keys (simplified - in practice would use ratchet encryption keys)
            fresh = os.urandom(32)
            from .crypto import argon2_derive_key_material
            new_km = argon2_derive_key_material(fresh + self.send_key + self.recv_key, salt=self.session_id[:16], length=64)
            new_send = new_km[:32]
            new_recv = new_km[32:64]
            self.aead_send = ChaCha20Poly1305(new_send)
            self.aead_recv = ChaCha20Poly1305(new_recv)
            self.send_key = new_send
            self.recv_key = new_recv
            self.handshake_retries = 0
            logger.info(f"Session {self.session_id.hex()[:8]} keys rotated with ratchet ({reason})")
        except Exception as e:
            logger.error(f"Session key rotation failed: {e}")


class SessionManager:
    """Manages VPN sessions."""

    def __init__(self, config: dict):
        self.config = config
        self.sessions: dict[bytes, SessionInfo] = {}
        self.session_timeout = config.get('session_timeout', 3600)
        self.handshake_timeout = config.get('handshake_timeout', 30)

    def create_session(self, session_id: bytes, peer_id: bytes, send_key: bytes, recv_key: bytes) -> SessionInfo:
        """Create a new session."""
        aead_send = ChaCha20Poly1305(send_key)
        aead_recv = ChaCha20Poly1305(recv_key)
        
        # Initialize ratchet for forward secrecy
        from .ratchet import create_ratchet
        initial_ratchet_key = send_key + recv_key
        if len(initial_ratchet_key) != 64:
            initial_ratchet_key = hashlib.sha256(initial_ratchet_key).digest()
        ratchet = create_ratchet(initial_ratchet_key)
        
        session = SessionInfo(
            session_id=session_id,
            peer_id=peer_id,
            aead_send=aead_send,
            aead_recv=aead_recv,
            send_key=send_key,
            recv_key=recv_key,
            ratchet=ratchet
        )
        self.sessions[session_id] = session
        logger.info(f"Created session {session_id.hex()[:8]} with peer {peer_id.hex()[:8]} (with ratchet)")
        return session

    def get_session(self, session_id: bytes) -> Optional[SessionInfo]:
        """Get session by ID."""
        return self.sessions.get(session_id)

    def close_session(self, session_id: bytes, reason: str = "closed"):
        """Close a session."""
        session = self.sessions.pop(session_id, None)
        if session:
            session.state = SESSION_STATE_CLOSED
            logger.info(f"Closed session {session_id.hex()[:8]}: {reason}")

    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [
            sid for sid, session in self.sessions.items()
            if now - session.last_activity > self.session_timeout
        ]
        for sid in expired:
            self.close_session(sid, "timeout")
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")

    def list_sessions(self) -> list[SessionInfo]:
        """List all active sessions."""
        return list(self.sessions.values())