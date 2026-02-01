import asyncio
import hashlib
import os
from types import SimpleNamespace

# Import the module under test
import main

# Shortcuts
PQVPNNode = main.PQVPNNode

# Fake PQ functions to avoid needing real liboqs in tests
SIG_PKSIZE = 64


def fake_pq_kem_encaps(peer_pk):
    # Return a ciphertext and a shared secret deterministically based on ct
    ct = os.urandom(32)
    ss = hashlib.sha256(ct).digest()
    return ct, ss


def fake_pq_kem_decaps(ct, sk):
    # Derive same shared secret from ciphertext
    ss = hashlib.sha256(ct).digest()
    return ss


def fake_pq_sig_keygen(alg=None):
    # Return (pk, sk) where sk encodes pk so signing can extract pk
    pk = os.urandom(SIG_PKSIZE)
    sk = b"SK" + pk
    return pk, sk


def fake_pq_sig_sign(sk, data, alg=None):
    # Extract public key from sk and compute signature as H(data || pk)
    try:
        pk = sk[2:]
    except Exception:
        pk = b""
    return hashlib.sha256((data or b"") + pk).digest()


def fake_pq_sig_verify_debug(pk, data, sig, alg=None):
    # Verify by recomputing expected signature
    try:
        # normalize pk to bytes
        if isinstance(pk, str):
            try:
                pkb = bytes.fromhex(pk)
            except Exception:
                pkb = pk.encode()
        else:
            pkb = bytes(pk)

        # normalize sig to bytes (handle hex string produced by .hex())
        if isinstance(sig, str):
            try:
                sigb = bytes.fromhex(sig)
            except Exception:
                try:
                    import base64 as _b64

                    sigb = _b64.b64decode(sig)
                except Exception:
                    sigb = sig.encode()
        else:
            sigb = bytes(sig)

        expected = hashlib.sha256((data or b"") + pkb).digest()
        # debug
        print(
            f"[TEST-DEBUG] verify: pk_len={len(pkb)} sig_len={len(sigb)} data_len={len(data or b'')} pk_hex={pkb.hex()[:16]} sig_hex={sigb.hex()[:16]} expected_hex={expected.hex()[:16]}"
        )
        # Return boolean to match pq_sig_verify's API in main.py
        return expected == sigb
    except Exception:
        return False


class FakeTransport:
    def __init__(self, local_node, peer_node):
        self.local = local_node
        self.peer = peer_node

    def sendto(self, data: bytes, addr):
        # Simulate UDP send: schedule the peer's datagram_received with sender address
        loop = asyncio.get_event_loop()
        # sender addr reported as local node's host/port
        sender = (self.local.host, int(self.local.port))
        print(
            f"[TEST-DEBUG] FakeTransport.sendto called: from {self.local.nickname} -> to {addr} len={len(data)}"
        )
        # Parse outer header and directly dispatch to peer handler coroutines
        try:
            if not data or len(data) < 16:
                return
            import struct

            try:
                version, ftype, next_hash, circuit_id, length = struct.unpack(
                    "!BB8sIH", data[:16]
                )
            except Exception:
                return

            payload = data[16 : 16 + length]

            # Map frame type to handler on PQVPNNode
            if ftype == main.FT_HELLO:
                coro = self.peer.handle_hello(
                    payload, sender, outer_next_hash=next_hash, circuit_id=circuit_id
                )
            elif ftype == main.FT_S1:
                coro = self.peer.handle_s1(
                    payload, sender, outer_next_hash=next_hash, circuit_id=circuit_id
                )
            elif ftype == main.FT_S2:
                coro = self.peer.handle_s2(
                    payload, sender, outer_next_hash=next_hash, circuit_id=circuit_id
                )
            else:
                # For other frames not needed in this test, ignore
                return

            loop.create_task(coro)
        except Exception as ex:
            print(f"[TEST-DEBUG] FakeTransport dispatch exception: {ex}")
            loop.call_soon(lambda: None)


def test_s1_s2_handshake_flow(tmp_path, monkeypatch):
    """Synchronous pytest wrapper that runs the async handshake test body via asyncio.run.

    This avoids requiring the pytest-asyncio plugin in the test environment.
    """

    async def _inner():
        # Patch main's PQ functions to fakes
        monkeypatch.setattr(main, "pq_kem_encaps", fake_pq_kem_encaps)
        monkeypatch.setattr(main, "pq_kem_decaps", fake_pq_kem_decaps)
        monkeypatch.setattr(main, "pq_sig_keygen", fake_pq_sig_keygen)
        monkeypatch.setattr(main, "pq_sig_sign", fake_pq_sig_sign)
        monkeypatch.setattr(main, "pq_sig_verify_debug", fake_pq_sig_verify_debug)
        # Prefer patching pq_sig_verify; if pq_sig_verify_debug doesn't exist allow creation
        monkeypatch.setattr(main, "pq_sig_verify", fake_pq_sig_verify_debug)
        monkeypatch.setattr(main, "pq_sig_verify_debug", fake_pq_sig_verify_debug, raising=False)

        # Ensure hybrid enforcement is satisfied (we fake OQSPY availability)
        monkeypatch.setattr(main, "OQSPY_AVAILABLE", True)
        monkeypatch.setattr(main, "OQSPY_KEMALG", "Kyber1024")
        monkeypatch.setattr(main, "OQSPY_SIGALG", "ML-FAKE-TEST")

        # Create minimal config files for two nodes
        cfg_a = tmp_path / "a.yaml"
        cfg_b = tmp_path / "b.yaml"
        cfg_a.write_text(
            """peer:\n  nickname: nodeA\nnetwork:\n  bind_host: 127.0.0.1\n  listen_port: 9005\n"""
        )
        cfg_b.write_text(
            """peer:\n  nickname: nodeB\nnetwork:\n  bind_host: 127.0.0.1\n  listen_port: 9006\n"""
        )

        # Instantiate nodes
        nodeA = PQVPNNode(str(cfg_a))
        nodeB = PQVPNNode(str(cfg_b))

        # Wire fake bidirectional transports using FakeTransport
        tA = FakeTransport(nodeA, nodeB)
        tB = FakeTransport(nodeB, nodeA)

        protoA = SimpleNamespace(transport=tA)
        protoB = SimpleNamespace(transport=tB)

        nodeA.protocol = protoA
        nodeB.protocol = protoB

        # Create PeerInfo representing nodeB for nodeA to initiate handshake
        bpb = None
        try:
            bpb = nodeB.brainpoolP512r1_pk.public_bytes(
                encoding=main.serialization.Encoding.X962,
                format=main.serialization.PublicFormat.UncompressedPoint,
            )
        except Exception:
            # fallback to empty bytes
            bpb = b""

        pinfoB = main.PeerInfo(
            peer_id=nodeB.my_id or (hashlib.sha256(b"nodeB").digest()),
            nickname=nodeB.nickname,
            address=(nodeB.host, nodeB.port),
            ed25519_pk=nodeB.ed25519_pk,
            brainpoolP512r1_pk=bpb,
            kyber_pk=nodeB.kyber_pk,
            mldsa_pk=nodeB.mldsa_pk,
        )

        # Initiate handshake from A to B
        print(
            f"[TEST-DEBUG] nodeA.protocol present? {hasattr(nodeA, 'protocol')} proto={getattr(nodeA, 'protocol', None)} proto.transport={getattr(getattr(nodeA, 'protocol', None), 'transport', None)}"
        )
        nodeA.initiate_handshake(pinfoB, (nodeB.host, nodeB.port))

        # Allow some time for async datagram handling and handshake reply
        await asyncio.sleep(0.5)

        # Check that both nodes have established sessions
        assert any(
            s.state == main.SESSION_STATE_ESTABLISHED for s in nodeA.sessions.values()
        ), "nodeA has no established session"
        assert any(
            s.state == main.SESSION_STATE_ESTABLISHED for s in nodeB.sessions.values()
        ), "nodeB has no established session"

        # Find session pairs and verify peer ids
        sessA = next(
            (
                s
                for s in nodeA.sessions.values()
                if s.remote_addr and s.remote_addr[1] == nodeB.port
            ),
            None,
        )
        sessB = next(
            (
                s
                for s in nodeB.sessions.values()
                if s.remote_addr and s.remote_addr[1] == nodeA.port
            ),
            None,
        )

        assert sessA is not None and sessB is not None
        # peer_ids should be reciprocally present
        assert sessA.peer_id == (nodeB.my_id or sessA.peer_id)
        assert sessB.peer_id == (nodeA.my_id or sessB.peer_id)

        # Clean up: nothing to close for fake transports

    # Execute async test body
    asyncio.run(_inner())
