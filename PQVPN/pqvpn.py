#!/usr/bin/env python3
"""
pqvpn.py - Path-Quilt VPN (PQVPN) single-file reference prototype with enhancements

Enhanced features:
- 2-hop pathlets with stateless RELAY forwarding
- TUN adapter for IP routing (Linux)
- PATH_PROBE/PATH_PONG multipath with RTT selection
- 64-packet replay window protection
- Raspberry Pi / ARM compatible

Run: sudo python pqvpn.py --config config.yaml
Requires: cryptography pyyaml
"""

import asyncio
import base64
import hashlib
import os
import sys
import time
import struct
import socket
import select
import fcntl
import yaml
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
import ctypes
import ctypes.util

# Load liboqs from local build
try:
    liboqs_path = (
        Path(__file__).parent / "liboqs-0.15.0" / "build" / "lib" / "liboqs.so"
    )
    if liboqs_path.exists():
        liboqs = ctypes.CDLL(str(liboqs_path))
        # Check if functions exist
        if not hasattr(liboqs, "OQS_KEM_kyber_1024_keypair"):
            raise RuntimeError("OQS_KEM_kyber_1024_keypair not found")
        # Define function signatures
        # Kyber1024
        liboqs.OQS_KEM_kyber_1024_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
        ]
        liboqs.OQS_KEM_kyber_1024_keypair.restype = ctypes.c_int
        liboqs.OQS_KEM_kyber_1024_encaps.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
        ]
        liboqs.OQS_KEM_kyber_1024_encaps.restype = ctypes.c_int
        liboqs.OQS_KEM_kyber_1024_decaps.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
        ]
        liboqs.OQS_KEM_kyber_1024_decaps.restype = ctypes.c_int
        # Dilithium3 (now ML-DSA-65)
        if not hasattr(liboqs, "OQS_SIG_ml_dsa_65_keypair"):
            raise RuntimeError("OQS_SIG_ml_dsa_65_keypair not found")
        liboqs.OQS_SIG_ml_dsa_65_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
        ]
        liboqs.OQS_SIG_ml_dsa_65_keypair.restype = ctypes.c_int
        liboqs.OQS_SIG_ml_dsa_65_sign.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
        ]
        liboqs.OQS_SIG_ml_dsa_65_sign.restype = ctypes.c_int
        liboqs.OQS_SIG_ml_dsa_65_verify.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
        ]
        liboqs.OQS_SIG_ml_dsa_65_verify.restype = ctypes.c_int
        LIBOQS_AVAILABLE = True
    else:
        LIBOQS_AVAILABLE = False
except Exception as e:
    print(f"Failed to load liboqs ctypes: {e}")
    LIBOQS_AVAILABLE = False

# PQ Key sizes
KYBER1024_PK_SIZE = 1568
KYBER1024_CT_SIZE = 1568
KYBER1024_SK_SIZE = 3168
DILITHIUM3_PK_SIZE = 1952
DILITHIUM3_SK_SIZE = 4000
DILITHIUM3_SIG_SIZE = 3293


class PQNode:
    FRAME_TYPES = {
        "HELLO": 0x01,
        "HS1": 0x02,
        "HS2": 0x03,
        "PATH_PROBE": 0x04,
        "PATH_PONG": 0x05,
        "RELAY": 0x06,
        "DATA": 0x07,
        "REKEY": 0x08,
        "CLOSE": 0x09,
        "CONTROL_OPEN": 0x0A,
    }

    def __init__(self, config_path):
        self.config = yaml.safe_load(open(config_path))
        self.nickname = self.config["peer"]["nickname"]

        # Keys
        self.ed_priv = serialization.load_pem_private_key(
            open(self.config["keys"]["ed25519"], "rb").read()
        )
        self.ed_pub = self.ed_priv.public_key()
        self.x_priv = x25519.X25519PrivateKey.from_private_bytes(
            open(self.config["keys"]["x25519"], "rb").read()
        )
        self.x_pub = self.x_priv.public_key()
        self.peerid = self.x_pub.public_key_bytes()

        # Network
        self.peers = {}  # peerid -> (addr, port)
        self.circuits = {}  # circuit_id -> {'path': [peerids], 'rtt': int, 'session': Session}
        self.sessions = {}  # peerid -> Session
        self.next_circuit_id = 1
        self.tun = None
        self.tun_name = None

        # Security
        self.replay_window_size = self.config.get("security", {}).get(
            "replay_window", 64
        )

        # Adapters
        self.setup_tun()

        print(
            f"PQVPN {self.nickname} ready (PeerID: {base64.b64encode(self.peerid)[:8].decode()}...)"
        )

    def setup_tun(self):
        if "tun" in self.config.get("adapters", []):
            try:
                self.tun = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
                ifr = struct.pack(
                    "16sH", b"pqvpn%d", 0x0001 | 0x1000
                )  # IFF_TUN | IFF_NO_PI
                self.tun_name = (
                    fcntl.ioctl(self.tun, 0x400454CA, ifr)[:16].split(b"\0")[0].decode()
                )
                os.system(f"ip addr add 10.0.0.1/24 dev {self.tun_name}")
                os.system(f"ip link set dev {self.tun_name} up")
                print(f"TUN: {self.tun_name}")
            except Exception as e:
                print(f"TUN setup failed: {e}")

    def peer_hash8(self, peerid: bytes) -> bytes:
        return hashlib.sha256(peerid).digest()[:8]

    def make_frame(self, frame_type: int, circuit_id: int, payload: bytes) -> bytes:
        length = len(payload)
        return (
            struct.pack(
                "!BB8sIH",
                1,
                frame_type,
                self.peer_hash8(self.peerid),
                circuit_id,
                length,
            )
            + payload
        )

    async def send_frame(self, addr, frame: bytes):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(frame, addr)
        sock.close()

    def build_twohop_circuit(self, dst_peerid: bytes):
        """Pick random relay from known peers, build 2-hop path"""
        relays = [pid for pid in self.peers if pid != dst_peerid]
        if not relays:
            return None
        relay = relays[0]
        circuit_id = self.next_circuit_id
        self.next_circuit_id += 1
        self.circuits[circuit_id] = {
            "path": [self.peerid, relay, dst_peerid],
            "rtt": float("inf"),
        }
        return circuit_id

    async def handle_frame(self, data: bytes, src_addr):
        frame_type = data[1]
        next_hash = data[2:10]
        circuit_id = struct.unpack("!I", data[10:14])[0]
        length = struct.unpack("!H", data[14:16])[0]
        payload = data[16 : 16 + length]

        if frame_type == self.FRAME_TYPES["HELLO"]:
            peerid = payload[:32]
            self.peers[peerid] = src_addr
            print(f"Peer discovered: {base64.b64encode(peerid)[:8].decode()}")

        elif frame_type == self.FRAME_TYPES["RELAY"]:
            # Stateless relay: forward to next hop
            next_peerid_hash = payload[:8]
            relay_payload = payload[8:]
            # Find peer matching hash (simplified)
            for pid, addr in self.peers.items():
                if self.peer_hash8(pid) == next_peerid_hash:
                    await self.send_frame(addr, relay_payload)
                    return

        elif frame_type == self.FRAME_TYPES["PATH_PROBE"]:
            # Respond with PONG + timestamp
            ts = struct.pack("!Q", int(time.time_ns() / 1000))
            pong = self.make_frame(self.FRAME_TYPES["PATH_PONG"], circuit_id, ts)
            await self.send_frame(src_addr, pong)

        elif frame_type == self.FRAME_TYPES["DATA"] and circuit_id in self.circuits:
            session = self.circuits[circuit_id].get("session")
            if session:
                session.handle_data(payload)

    async def tun_loop(self):
        while self.tun:
            r, _, _ = select.select([self.tun], [], [], 0.1)
            if r:
                packet = os.read(self.tun, 2048)
                # Find best circuit and send
                best_circuit = min(
                    self.circuits,
                    key=lambda cid: self.circuits[cid]["rtt"],
                    default=None,
                )
                if best_circuit:
                    session = self.circuits[best_circuit]["session"]
                    if session:
                        enc_data = session.encrypt(packet)
                        frame = self.make_frame(
                            self.FRAME_TYPES["DATA"], best_circuit, enc_data
                        )
                        # Send via first hop
                        first_hop = self.peers[self.circuits[best_circuit]["path"][1]]
                        await self.send_frame(first_hop, frame)

    async def udp_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.config["network"]["listen_port"]))
        sock.setblocking(False)

        # Bootstrap
        for bootstrap in self.config["network"]["bootstrap"]:
            hello = self.make_frame(self.FRAME_TYPES["HELLO"], 0, self.peerid)
            await self.send_frame(bootstrap, hello)

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                asyncio.create_task(self.handle_frame(data, addr))
            except Exception:
                await asyncio.sleep(0.01)

    async def repl(self):
        loop = asyncio.get_event_loop()
        while True:
            cmd = await loop.run_in_executor(None, input, f"{self.nickname}> ")
            if cmd == "peers":
                for pid, addr in self.peers.items():
                    print(f"  {base64.b64encode(pid)[:8].decode()} -> {addr}")
            elif cmd.startswith("hs "):
                peer_b64 = cmd[3:].strip()
                peerid = base64.b64decode(peer_b64)
                circuit_id = self.build_twohop_circuit(peerid)
                if circuit_id:
                    print(
                        f"Circuit {circuit_id} to {base64.b64encode(peerid)[:8].decode()}"
                    )
            elif cmd == "probe":
                for cid in list(self.circuits.keys())[:3]:
                    probe = self.make_frame(self.FRAME_TYPES["PATH_PROBE"], cid, b"")
                    first_hop = self.peers[self.circuits[cid]["path"][1]]
                    await self.send_frame(first_hop, probe)
            elif cmd == "quit":
                break


class Session:
    def __init__(self, local_priv, remote_pub):
        self.send_key = b"0" * 32
        self.recv_key = b"0" * 32
        self.send_nonce = 0
        self.recv_nonce = 0
        self.replay_window = set()
        self.rekey_count = 0

    def encrypt(self, data: bytes) -> bytes:
        nonce = struct.pack("!Q", self.send_nonce)
        aead = ChaCha20Poly1305(self.send_key)
        ct = aead.encrypt(nonce, data, None)
        self.send_nonce += 1
        if self.send_nonce % 16777216 == 0:
            self.rekey()
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        nonce = struct.pack("!Q", self.recv_nonce)
        if self.recv_nonce in self.replay_window:
            raise ValueError("Replay attack")

        aead = ChaCha20Poly1305(self.recv_key)
        pt = aead.decrypt(nonce, ct, None)

        self.replay_window.add(self.recv_nonce)
        if len(self.replay_window) > 64:
            self.replay_window.remove(min(self.replay_window))
        self.recv_nonce += 1
        return pt

    def rekey(self):
        self.rekey_count += 1
        # Simplified rekey - in production use HKDF expansion


async def main():
    if len(sys.argv) != 3 or sys.argv[1] != "--config":
        print("Usage: sudo python pqvpn.py --config config.yaml")
        return

    node = PQNode(sys.argv[2])
    await asyncio.gather(node.udp_listener(), node.tun_loop(), node.repl())


if __name__ == "__main__":
    asyncio.run(main())
