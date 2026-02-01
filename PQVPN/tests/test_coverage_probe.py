import os
import pytest

import main as _main
from main import PQVPNNode, canonical_sign_bytes, SessionInfo
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Monkeypatch PQ/oqs functions to avoid requiring liboqs at test time
_main.OQSPY_AVAILABLE = True
_main.OQSPY_KEMALG = _main.OQSPY_KEMALG or "Kyber1024"
_main.OQSPY_SIGALG = _main.OQSPY_SIGALG or "ML-DSA-87"

# Provide simple deterministic stubs that return appropriately-sized bytes


def _stub_pq_kem_keygen():
    return (b"\x11" * _main.KYBER1024_PKSIZE, b"\x22" * _main.KYBER1024_SKSIZE)


def _stub_pq_sig_keygen(alg=None):
    return (b"\x33" * _main.SIG_PKSIZE, b"\x44" * _main.SIG_SKSIZE)


_main.pq_kem_keygen = _stub_pq_kem_keygen
_main.pq_sig_keygen = _stub_pq_sig_keygen


def make_cfg(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        """peer:\n  nickname: covtest\nnetwork:\n  bind_host: 127.0.0.1\n  listen_port: 0\n"""
    )
    return str(cfg)


@pytest.mark.timeout(30)
def test_coverage_probe_basic(tmp_path):
    cfgpath = make_cfg(tmp_path)

    node = PQVPNNode(cfgpath)

    # exercise canonical signing helper
    obj = {"a": 1, "b": 2}
    cb = canonical_sign_bytes(obj)
    assert isinstance(cb, bytes)

    # session salt and peer_hash8
    peer = b"peerid1234567890abcd"
    s = node.session_salt(peer)
    assert isinstance(s, bytes) and len(s) == 16
    h8 = node.peer_hash8(peer)
    assert isinstance(h8, bytes) and len(h8) == 8

    # create a dummy session and test nonce handling
    send_key = b"\x00" * 32
    recv_key = b"\x01" * 32
    aead_send = ChaCha20Poly1305(send_key)
    aead_recv = ChaCha20Poly1305(recv_key)

    sess = SessionInfo(
        session_id=b"sid12345",
        peer_id=peer,
        aead_send=aead_send,
        aead_recv=aead_recv,
    )

    # record in node
    node.sessions[sess.session_id] = sess
    node.sessions_by_peer_id[sess.peer_id] = sess

    # build a valid nonce (4-byte iv + 8-byte counter)
    nonce = sess.session_iv + (0).to_bytes(8, "big")
    ok = node.check_and_record_nonce(sess, nonce)
    assert ok is True

    # replay same nonce must be rejected
    ok2 = node.check_and_record_nonce(sess, nonce)
    assert ok2 is False

    # test make_outer_frame
    payload = b"hello"
    frame = node.make_outer_frame(0x00, b"\x00" * 8, 1, payload)
    assert isinstance(frame, bytes)
    # cleanup
    try:
        if not node.persistent_keys and os.path.isdir(node.keys_dir):
            # remove ephemeral keys dir created by node
            import shutil

            shutil.rmtree(node.keys_dir, ignore_errors=True)
    except Exception:
        pass
