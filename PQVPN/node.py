# pqvpn/node.py
import asyncio
import os
import select
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from .crypto import KeyBundle, hkdf, AEADState
from .replay_window import ReplayWindow
from .rate_limit import TokenBucket
from .framing import (
    parse_outer_header,
    build_outer_header,
    FT_HELLO,
    FT_RELAY,
    FT_DATA,
    peer_hash8,
)
from .routing.simple import PathManager
from .adapters.tun import TunDevice


class PeerSession:
    def __init__(self, peer_id: bytes, shared_secret: bytes):
        self.peer_id = peer_id
        rx_key = hkdf(b"rx", shared_secret)
        tx_key = hkdf(b"tx", shared_secret)
        self.rx = AEADState(rx_key)
        self.tx = AEADState(tx_key)
        self.rx_nonce = 0
        self.tx_nonce = 0
        self.replay = ReplayWindow(size=64)
        self.rate = TokenBucket(capacity=100, refill_rate=50.0)

    def encrypt_packet(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        if not self.rate.consume(1.0):
            raise ValueError("Rate limited")
        out = self.tx.seal(plaintext, aad)
        self.tx_nonce += 1
        return out

    def decrypt_packet(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        if not self.replay.check_and_add(self.rx_nonce):
            raise ValueError("Replay detected")
        pt = self.rx.open(ciphertext, aad)
        self.rx_nonce += 1
        return pt


class Node:
    def __init__(self, config, keybundle: KeyBundle):
        self.config = config
        self.keys = keybundle
        self.local_id = keybundle.x_pub.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.peers = {}  # peer_id -> PeerSession
        self.pathman = PathManager(self.local_id)
        self.tun = None
        self.tun_dev = None
        self.transport = None

    def short_id(self) -> str:
        return base64.urlsafe_b64encode(
            hashlib.sha256(self.local_id).digest()[:8]
        ).decode()[:8]

    def short_peer_id(self, peer_id: bytes) -> str:
        return base64.urlsafe_b64encode(hashlib.sha256(peer_id).digest()[:8]).decode()[
            :8
        ]

    def setup_tun(self):
        if self.config.adapters.get("tun", {}).get("enabled", False):
            try:
                self.tun_dev = TunDevice("pqtun0")
                self.tun = self.tun_dev.open()
                name = self.tun_dev.name
                os.system(f"ip addr add 10.0.0.1/24 dev {name}")
                os.system(f"ip link set {name} up")
                print(f"✅ TUN: {name}")
                asyncio.create_task(self.tun_loop())
            except Exception as e:
                print(f"❌ TUN failed: {e}")

    async def tun_loop(self):
        while self.tun:
            r, _, _ = select.select([self.tun], [], [], 0.01)
            if self.tun in r:
                packet = os.read(self.tun, 1500)
                # Send to first peer via best path
                for peer_id in self.peers:
                    await self.send_data(peer_id, packet)
                    break

    async def start(self, transport):
        self.transport = transport
        print(f"✅ PQNode '{self.config.node_name}' ready (ID: {self.short_id()})")

    async def dispatch_frame(self, data: bytes, addr):
        try:
            ver, ftype, next_hash, circuit, length, payload = parse_outer_header(data)
            if ver != 1:
                return
        except Exception:
            return

        if ftype == FT_HELLO:
            await self._handle_hello(payload, addr)
        elif ftype == FT_RELAY:
            await self._handle_relay(payload, addr)
        elif ftype == FT_DATA:
            await self._handle_data(payload, addr)
        else:
            print(f"📦 Frame {ftype:02x}")

    async def _handle_hello(self, payload: bytes, addr):
        if len(payload) >= 32:
            peer_id = payload[:32]
            self.pathman.add_peer(peer_id, addr)
            # Demo shared secret (production: proper handshake)
            shared = b"demo-shared-secret-for-testing"
            self.peers[peer_id] = PeerSession(peer_id, shared)
            print(f"👋 Peer {self.short_peer_id(peer_id)} -> {addr}")

    async def _handle_relay(self, payload: bytes, addr):
        # Stateless relay: next_hash8 + inner_frame
        if len(payload) >= 8:
            next_hash = payload[:8]
            inner = payload[8:]
            # Find peer by hash
            for peer_id in self.peers:
                if peer_hash8(peer_id) == next_hash:
                    endpoint = self.pathman.paths[peer_id]["endpoint"]
                    self.transport.sendto(inner, endpoint)
                    print("🔄 RELAY forwarded")
                    return

    async def _handle_data(self, payload: bytes, addr):
        # Find peer by addr
        peer_id = None
        for pid, endpoint in self.pathman.paths.items():
            if endpoint["endpoint"] == addr:
                peer_id = pid
                break

        sess = self.peers.get(peer_id)
        if sess:
            try:
                pt = sess.decrypt_packet(payload)
                if self.tun:
                    os.write(self.tun, pt[:1500])
                else:
                    print(f"📨 DATA {len(pt)} bytes from {self.short_peer_id(peer_id)}")
            except Exception as e:
                print(f"❌ Decrypt fail: {e}")

    async def send_data(self, peer_id: bytes, data: bytes):
        path = self.pathman.build_pathlet(peer_id)
        if not path or len(path) < 2:
            return

        sess = self.peers.get(peer_id)
        if not sess:
            return

        try:
            enc = sess.encrypt_packet(data)
            frame = build_outer_header(FT_DATA, b"\x00" * 8, 0, enc)

            # Wrap in RELAY for 2-hop
            next_hop_hash = self.pathman.get_next_hop(path, 1)
            relay_frame = build_outer_header(FT_RELAY, next_hop_hash, 0, frame)

            endpoint = self.pathman.paths[peer_id]["endpoint"]
            self.transport.sendto(relay_frame, endpoint)
            print(
                f"📤 Sent {len(data)} bytes via 2-hop to {self.short_peer_id(peer_id)}"
            )
        except Exception as e:
            print(f"❌ Send fail: {e}")
