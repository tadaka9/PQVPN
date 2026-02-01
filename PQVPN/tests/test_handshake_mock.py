import json
import pytest
import main
import hashlib
import os

from main import PQVPNNode


class DummyTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


class MockProtocol:
    def __init__(self, transport):
        self.transport = transport


# Simple fake PQ implementations to allow handshake tests to run without liboqs
def fake_pq_kem_encaps(peer_pk):
    ct = os.urandom(32)
    ss = hashlib.sha256(ct).digest()
    return ct, ss


def fake_pq_kem_decaps(ct, sk):
    return hashlib.sha256(ct).digest()


def fake_pq_sig_keygen(alg=None):
    pk = os.urandom(64)
    sk = b"SK" + pk
    return pk, sk


def fake_pq_sig_sign(sk, data, alg=None):
    try:
        pk = sk[2:]
    except Exception:
        pk = b""
    return hashlib.sha256((data or b"") + pk).digest()


def fake_pq_sig_verify(pk, data, sig, alg=None):
    try:
        if isinstance(pk, str):
            try:
                pkb = bytes.fromhex(pk)
            except Exception:
                pkb = pk.encode()
        else:
            pkb = bytes(pk)
        if isinstance(sig, str):
            try:
                sigb = bytes.fromhex(sig)
            except Exception:
                import base64 as _b64

                try:
                    sigb = _b64.b64decode(sig)
                except Exception:
                    sigb = sig.encode()
        else:
            sigb = bytes(sig)

        expected = hashlib.sha256((data or b"") + pkb).digest()
        return expected == sigb
    except Exception:
        return False


# Wire fakes into main module
main.pq_kem_encaps = fake_pq_kem_encaps
main.pq_kem_decaps = fake_pq_kem_decaps
main.pq_sig_keygen = fake_pq_sig_keygen
main.pq_sig_sign = fake_pq_sig_sign
main.pq_sig_verify = fake_pq_sig_verify
main.OQSPY_AVAILABLE = True
main.OQSPY_KEMALG = "Kyber1024"
main.OQSPY_SIGALG = "ML-FAKE-TEST"


@pytest.mark.asyncio
async def test_initiator_to_responder_s1_s2_flow(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        """peer:\n  nickname: test\nnetwork:\n  bind_host: 127.0.0.1\n  listen_port: 9001\n"""
    )

    # Create two nodes with ephemeral keys dir
    node_a = PQVPNNode(str(cfg))
    node_b = PQVPNNode(str(cfg))

    # Replace protocol/transport with mock
    t_a = DummyTransport()
    node_a.protocol = MockProtocol(t_a)
    node_a.transport = t_a

    t_b = DummyTransport()
    node_b.protocol = MockProtocol(t_b)
    node_b.transport = t_b

    # Create PeerInfo for node_b and initiate handshake from node_a
    pinfo = type("P", (), {})()
    pinfo.kyber_pk = node_b.kyber_pk
    # Use brainpoolP512r1 public key (replaces x25519 in the updated code)
    if hasattr(node_b, "brainpoolP512r1_pk") and hasattr(
        node_b.brainpoolP512r1_pk, "public_bytes"
    ):
        try:
            pinfo.brainpoolP512r1_pk = node_b.brainpoolP512r1_pk.public_bytes(
                encoding=node_b.brainpoolP512r1_pk.public_bytes.__self__.encoding,
                format=node_b.brainpoolP512r1_pk.public_bytes.__self__.format,
            )
        except Exception:
            pinfo.brainpoolP512r1_pk = b""
    else:
        pinfo.brainpoolP512r1_pk = b""
    pinfo.ed25519_pk = node_b.ed25519_pk
    pinfo.mldsa_pk = node_b.mldsa_pk
    pinfo.nickname = "peerb"

    addr = ("127.0.0.1", 9999)

    # Initiate handshake
    node_a.initiate_handshake(pinfo, addr)

    # Expect that node_a's DummyTransport received an FT_S1 frame
    assert len(t_a.sent) >= 1
    frame, dest = t_a.sent[-1]
    assert dest == addr

    # Extract payload and pass to node_b.handle_s1
    # skip outer header (16 bytes)
    payload = frame[16:]

    await node_b.handle_s1(payload, addr)

    # node_b should have sent FT_S2
    assert len(t_b.sent) >= 1
    frame2, dest2 = t_b.sent[-1]
    assert dest2 == addr

    # Extract S2 payload and pass to node_a.handle_s2
    payload2 = frame2[16:]
    await node_a.handle_s2(payload2, addr)

    # Now both nodes should have established sessions (pending_handshakes cleared)
    assert any(s.state == "ESTABLISHED" for s in node_a.sessions.values())
    assert any(s.state == "ESTABLISHED" for s in node_b.sessions.values())


@pytest.mark.asyncio
async def test_s2_bad_signature_logs(tmp_path, caplog):
    cfg = tmp_path / "cfg2.yaml"
    cfg.write_text(
        """peer:\n  nickname: test2\nnetwork:\n  bind_host: 127.0.0.1\n  listen_port: 9002\n"""
    )

    node_a = PQVPNNode(str(cfg))
    node_b = PQVPNNode(str(cfg))

    t_a = DummyTransport()
    node_a.protocol = MockProtocol(t_a)
    node_a.transport = t_a

    t_b = DummyTransport()
    node_b.protocol = MockProtocol(t_b)
    node_b.transport = t_b

    pinfo = type("P", (), {})()
    pinfo.kyber_pk = node_b.kyber_pk
    # Use brainpoolP512r1 public key
    if hasattr(node_b, "brainpoolP512r1_pk") and hasattr(
        node_b.brainpoolP512r1_pk, "public_bytes"
    ):
        try:
            pinfo.brainpoolP512r1_pk = node_b.brainpoolP512r1_pk.public_bytes(
                encoding=node_b.brainpoolP512r1_pk.public_bytes.__self__.encoding,
                format=node_b.brainpoolP512r1_pk.public_bytes.__self__.format,
            )
        except Exception:
            pinfo.brainpoolP512r1_pk = b""
    else:
        pinfo.brainpoolP512r1_pk = b""
    pinfo.ed25519_pk = node_b.ed25519_pk
    pinfo.mldsa_pk = node_b.mldsa_pk
    pinfo.nickname = "peerb"

    addr = ("127.0.0.1", 9998)

    node_a.initiate_handshake(pinfo, addr)
    frame, dest = t_a.sent[-1]
    payload = frame[16:]

    # Make node_b handle S1 but tamper S2 signature before node_a handles it.
    await node_b.handle_s1(payload, addr)
    # tamper node_b's last sent S2
    frame2, dest2 = t_b.sent[-1]
    payload2 = frame2[16:]
    try:
        j = json.loads(payload2)
        j["mldsa_sig"] = "00" * 64  # invalid signature
        bad_payload = json.dumps(j, separators=(",", ":"), sort_keys=True).encode()
        await node_a.handle_s2(bad_payload, addr)
    except Exception:
        pass

    # Expect a warning logged about S2 signature verification (accept several variants)
    assert any(
        ("S2 signature verification failed" in rec.message)
        or ("S2 signature policy" in rec.message)
        or ("hybrid verification failed" in rec.message)
        for rec in caplog.records
    )
