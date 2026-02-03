# src/pqvpn/discovery.py
"""
Discovery module for PQVPN.

Implements DHT 2.0: Secure DHT with authentication, encryption, Sybil resistance, eclipse prevention, and PQ crypto integration.
"""

import asyncio
import hashlib
import json
import logging
import secrets
import statistics  # For anomaly detection
import time
from dataclasses import dataclass, field
from typing import Any

# Assume liboqs for PQ crypto
try:
    import oqs  # type: ignore
except ImportError:
    oqs = None

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .bootstrap import get_bootstrap_peers

logger = logging.getLogger(__name__)

@dataclass
class NodeInfo:
    node_id: bytes
    public_key: bytes  # PQ signature public key
    address: tuple[str, int]
    last_seen: float = 0.0
    reputation: float = 0.5  # Initial reputation 0.5
    invalid_responses: int = 0  # For poisoning detection
    quarantined: bool = False
    pow_nonce: bytes = field(default_factory=lambda: secrets.token_bytes(32))  # PoW nonce

@dataclass
class DHTConfig:
    k: int = 20  # k-bucket size
    alpha: int = 3  # concurrency parameter
    id_bits: int = 256  # node ID bits
    pow_difficulty: int = 16  # PoW difficulty for Sybil resistance

class SecureDHT:
    """
    DHT 2.0 implementation with security measures.
    """

    def __init__(self, node_id: bytes, private_key: bytes, config: DHTConfig = None):
        self.node_id = node_id
        self.private_key = private_key
        self.config = config or DHTConfig()
        self.routing_table: dict[int, list[NodeInfo]] = {}
        self.data_store: dict[bytes, dict] = {}  # Store signed data dicts
        self.peers: dict[bytes, NodeInfo] = {}
        self.running = False
        self.response_times: dict[bytes, list[float]] = {}  # For anomaly detection

        # PQ crypto setup
        if oqs:
            self.sig_alg = oqs.Signature("Dilithium5")  # Example PQ sig
            self.kem_alg = oqs.KeyEncapsulation("Kyber1024")  # Example PQ KEM
        else:
            raise RuntimeError("liboqs not available for PQ crypto")

        # Generate keypair if not provided
        self.sig_alg.generate_keypair()
        self.public_key = self.sig_alg.export_public_key()

    async def start(self, bootstrap_nodes: list[NodeInfo]):
        self.running = True
        # Bootstrap
        for node in bootstrap_nodes:
            await self._add_node(node)
        # Start maintenance tasks
        asyncio.create_task(self._maintain_routing_table())

    async def stop(self):
        self.running = False

    def _distance(self, a: bytes, b: bytes) -> int:
        return int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')

    def _bucket_index(self, node_id: bytes) -> int:
        dist = self._distance(self.node_id, node_id)
        return dist.bit_length() - 1 if dist else 0

    async def _add_node(self, node: NodeInfo):
        # Validate node: check PoW for Sybil resistance
        if not hasattr(node, 'pow_nonce') or not self._verify_pow(node.node_id, node.pow_nonce):
            logger.warning(f"Node {node.node_id.hex()[:8]} failed PoW validation, rejecting")
            return

        # Check for impersonation: ensure node_id matches public_key or something (placeholder)
        # For simplicity, assume node_id is hash of public_key
        expected_id = hashlib.sha256(node.public_key).digest()
        if node.node_id != expected_id:
            logger.warning(f"Node ID mismatch for {node.node_id.hex()[:8]}, possible impersonation")
            return

        bucket_idx = self._bucket_index(node.node_id)
        bucket = self.routing_table.setdefault(bucket_idx, [])
        if len(bucket) < self.config.k:
            bucket.append(node)
        else:
            # Prefer higher reputation
            lrs = min(bucket, key=lambda n: (n.reputation, n.last_seen))
            if lrs.reputation < node.reputation or not await self._ping(lrs):
                bucket.remove(lrs)
                bucket.append(node)
        self.peers[node.node_id] = node

    async def _ping(self, node: NodeInfo) -> bool:
        # Implement ping with secure message
        # For now, assume always true
        return True

    async def find_node(self, target_id: bytes) -> list[NodeInfo]:
        # Iterative find node with security
        closest = self._get_closest_nodes(target_id, self.config.alpha)
        queried = set()
        while closest and len(closest) < self.config.k:
            for node in closest:
                if node.node_id in queried:
                    continue
                queried.add(node.node_id)
                # Send secure find_node query
                response = await self._send_find_node(node, target_id)
                if response:
                    for new_node in response.get('nodes', []):
                        await self._add_node(new_node)
            closest = self._get_closest_nodes(target_id, self.config.alpha)

        return self._get_closest_nodes(target_id, self.config.k)

    def _get_closest_nodes(self, target_id: bytes, count: int) -> list[NodeInfo]:
        candidates = []
        for bucket in self.routing_table.values():
            candidates.extend(bucket)
        # Sort by distance, then by reputation (higher first), exclude quarantined
        candidates = [n for n in candidates if not n.quarantined]
        candidates.sort(key=lambda n: (self._distance(n.node_id, target_id), -n.reputation))
        return candidates[:count]

    async def _send_find_node(self, node: NodeInfo, target_id: bytes) -> dict:
        # Secure message sending
        message = {
            'type': 'find_node',
            'target': target_id.hex(),
            'sender_id': self.node_id.hex(),
            'timestamp': time.time()
        }
        # Sign message
        msg_bytes = json.dumps(message, sort_keys=True).encode()
        signature = self.sig_alg.sign(msg_bytes)
        message['signature'] = signature.hex()

        # Encrypt with shared secret (simplified, use KEM)
        shared_secret = await self._establish_shared_secret(node)
        encrypted = self._encrypt_message(msg_bytes, shared_secret)

        # Send via network (placeholder)
        # Assume response is received
        response = {}  # Placeholder
        return response

    async def _establish_shared_secret(self, node: NodeInfo) -> bytes:
        # Use PQ KEM to establish shared secret
        ciphertext, shared_secret = self.kem_alg.encap_secret(node.public_key)
        # In real impl, send ciphertext and receive response
        return shared_secret

    def _encrypt_message(self, plaintext: bytes, key: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, b'')
        return nonce + ciphertext

    def _decrypt_message(self, ciphertext: bytes, key: bytes) -> bytes:
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ct, b'')

    def _verify_pow(self, node_id: bytes, nonce: bytes) -> bool:
        # Check PoW: hash(node_id + nonce) has leading zeros
        data = node_id + nonce
        h = hashlib.sha256(data).digest()
        return h[:self.config.pow_difficulty // 8].count(0) == self.config.pow_difficulty // 8

    def generate_pow(self, node_id: bytes) -> bytes:
        nonce = secrets.token_bytes(32)
        while not self._verify_pow(node_id, nonce):
            nonce = secrets.token_bytes(32)
        return nonce

    async def store(self, key: bytes, value: Any, ttl: int = 3600):
        # Store with signature
        data = {
            'key': key.hex(),
            'value': value,
            'ttl': ttl,
            'timestamp': time.time(),
            'owner': self.node_id.hex()
        }
        msg_bytes = json.dumps(data, sort_keys=True).encode()
        signature = self.sig_alg.sign(msg_bytes)
        data['signature'] = signature.hex()

        # Validate own data
        if not self._validate_data(data):
            logger.error("Failed to validate own data")
            return

        self.data_store[key] = data  # Store locally

        # Find responsible nodes
        nodes = await self.find_node(key)
        confirmations = 0
        for node in nodes:
            success = await self._send_store(node, data)
            if success:
                confirmations += 1
                self._update_reputation(node.node_id, True)
            else:
                self._update_reputation(node.node_id, False)
        # Require majority confirmation
        if confirmations < len(nodes) // 2 + 1:
            logger.warning("Insufficient confirmations for store")

    async def _send_store(self, node: NodeInfo, data: dict) -> bool:
        # Send secure store
        # Placeholder: assume success if node not quarantined
        return not node.quarantined

    async def get(self, key: bytes) -> Any:
        nodes = await self.find_node(key)
        responses = {}
        for node in nodes:
            start_time = time.time()
            value_data = await self._send_get(node, key)
            response_time = time.time() - start_time
            if self._detect_anomaly(node.node_id, response_time):
                self._quarantine_node(node.node_id)
                continue
            if value_data and self._validate_data(value_data):
                responses[node.node_id] = value_data
                self._update_reputation(node.node_id, True)
            else:
                self._update_reputation(node.node_id, False)
                node.invalid_responses += 1
                if node.invalid_responses > 5:
                    self._quarantine_node(node.node_id)

        # Cross-verification: majority vote
        if not responses:
            return None
        values = list(responses.values())
        # Simple majority: most common value
        from collections import Counter
        value_counts = Counter(json.dumps(v['value'], sort_keys=True) for v in values)
        most_common = value_counts.most_common(1)[0]
        if most_common[1] > len(values) // 2:
            return json.loads(most_common[0])
        else:
            logger.warning("No majority consensus for get")
            return None

    async def _send_get(self, node: NodeInfo, key: bytes) -> dict:
        # Secure get
        # Placeholder
        return self.data_store.get(key, {})

    async def _maintain_routing_table(self):
        while self.running:
            # Random walks, reshuffling, etc.
            await asyncio.sleep(300)  # Every 5 min

    def _validate_data(self, data: dict) -> bool:
        # Validate format and signature
        required = ['key', 'value', 'ttl', 'timestamp', 'owner', 'signature']
        if not all(k in data for k in required):
            return False
        try:
            key = bytes.fromhex(data['key'])
            owner = bytes.fromhex(data['owner'])
            sig = bytes.fromhex(data['signature'])
            msg = json.dumps({k: data[k] for k in required[:-1]}, sort_keys=True).encode()

            # Freshness check: ensure timestamp is recent and TTL not expired
            now = time.time()
            if data['timestamp'] > now + 60 or data['timestamp'] < now - data['ttl']:
                logger.warning("Data is stale or future-dated")
                return False

            # Lookup public key
            if owner == self.node_id:
                pub_key = self.public_key
            else:
                peer = self.peers.get(owner)
                if not peer:
                    return False
                pub_key = peer.public_key

            return self.sig_alg.verify(msg, sig, pub_key)
        except:
            return False

    def _update_reputation(self, node_id: bytes, success: bool):
        node = self.peers.get(node_id)
        if not node or node.quarantined:
            return
        delta = 0.1 if success else -0.2
        node.reputation = max(0.0, min(1.0, node.reputation + delta))

    def _detect_anomaly(self, node_id: bytes, response_time: float) -> bool:
        times = self.response_times.setdefault(node_id, [])
        times.append(response_time)
        if len(times) > 10:
            times.pop(0)
        if len(times) < 5:
            return False
        mean = statistics.mean(times)
        stdev = statistics.stdev(times)
        return abs(response_time - mean) > 2 * stdev

    def _quarantine_node(self, node_id: bytes):
        node = self.peers.get(node_id)
        if node:
            node.quarantined = True
            logger.warning(f"Quarantined node {node_id.hex()[:8]} for suspected poisoning")

class Discovery:
    """Discovery subsystem using DHT 2.0."""

    def __init__(self, node):
        self.node = node
        self.config = node.config.get("discovery", {})
        self.enabled = self.config.get("enabled", True)
        self.dht = None
        self._started = False
        self._server = None

    async def start(self):
        if not self.enabled:
            return

        # Generate node ID and keys
        node_id = hashlib.sha256(self.node.my_id).digest()
        # Assume private key from node
        private_key = getattr(self.node, 'pq_private_key', secrets.token_bytes(32))

        bootstrap_nodes = await self._get_bootstrap_nodes()

        self.dht = SecureDHT(node_id, private_key)
        await self.dht.start(bootstrap_nodes)
        self._started = True
        logger.info("DHT 2.0 Discovery started")

    async def stop(self):
        if self.dht:
            await self.dht.stop()
        self._started = False

    async def _get_bootstrap_nodes(self) -> list[NodeInfo]:
        peers = await get_bootstrap_peers()
        nodes = []
        for peer in peers:
            # Convert to NodeInfo, assume public keys from somewhere
            node_info = NodeInfo(
                node_id=hashlib.sha256(peer.encode()).digest(),  # Placeholder
                public_key=secrets.token_bytes(32),  # Placeholder
                address=(peer.split(':')[0], int(peer.split(':')[1]))
            )
            nodes.append(node_info)
        return nodes

    async def publish_peer_record(self):
        if not self.dht:
            return
        record = self._build_record()
        await self.dht.store(hashlib.sha256(self.node.my_id).digest(), record)

    def _build_record(self):
        return {
            'peerid': self.node.my_id.hex(),
            'nickname': getattr(self.node, 'nickname', ''),
            'addr': getattr(self.node, 'address', ''),
            'public_key': self.dht.public_key.hex() if self.dht else '',
            'ts': time.time()
        }