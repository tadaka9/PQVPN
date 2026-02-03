# tests/test_session.py
"""Tests for session module."""

from pqvpn.session import SessionInfo, SessionManager


def test_session_manager():
    """Test session manager."""
    config = {"session_timeout": 1800, "handshake_timeout": 15}
    manager = SessionManager(config)
    assert manager.session_timeout == 1800
    assert manager.handshake_timeout == 15


def test_session_info():
    """Test SessionInfo dataclass."""
    import os

    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    key = os.urandom(32)
    aead = ChaCha20Poly1305(key)
    session = SessionInfo(
        session_id=b"session_id",
        peer_id=b"peer_id",
        aead_send=aead,
        aead_recv=aead,
        send_key=key,
        recv_key=key
    )
    assert session.session_id == b"session_id"
    assert session.state == "PENDING"
    assert len(session.session_iv) == 4